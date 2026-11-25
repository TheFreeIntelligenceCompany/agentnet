//! Seeded random schedules of loss / duplication / reordering / offline periods /
//! restarts over N messages: always exactly-once inbox rows and all `delivered`.

mod common;

use std::collections::HashSet;

use agentnet_core::api::*;
use common::*;

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn rcfg(seed: u64) -> agentnet_core::NodeConfig {
    cfg_with(|c| {
        c.delivery.jitter_seed = Some(seed);
        c.delivery.max_attempts = 10_000; // see docs: acks are only re-sent in answer to retries
        c.delivery.default_ttl_s = 86_400;
    })
}

async fn run_seed(seed: u64) {
    let mut rng = seed.wrapping_mul(7919).wrapping_add(1);
    let w = World::new();
    let mut a = w.agent("a", rcfg(seed));
    let mut b = w.agent("b", rcfg(seed + 1000));
    exchange(&a, &b).await;
    let _ = a.node.step_receive().await;
    let _ = b.node.step_receive().await;
    let n_msgs = 12;
    let mut sent: Vec<String> = vec![];
    let mut drops_left = 12u32;
    for _ in 0..250 {
        match splitmix(&mut rng) % 14 {
            0 | 1 if sent.len() < n_msgs => {
                let id = a.send(&b, &format!("m{}", sent.len())).await.message_id;
                sent.push(id);
            }
            2 => w.advance((splitmix(&mut rng) % 6000) as i64),
            3 => {
                let _ = a.node.step_send().await;
            }
            4 => {
                let _ = b.node.step_send().await;
            }
            5 => {
                let _ = a.node.step_receive().await;
            }
            6 => {
                let _ = b.node.step_receive().await;
            }
            7 if drops_left > 0 => {
                let k = ((splitmix(&mut rng) % 3) as u32).min(drops_left);
                drops_left -= k;
                if splitmix(&mut rng).is_multiple_of(2) {
                    a.transport.drop_next_publishes(k)
                } else {
                    b.transport.drop_next_publishes(k)
                }
            }
            8 => {
                let k = 1 + (splitmix(&mut rng) % 4) as u32;
                b.transport.set_duplicate_delivery(k);
                a.transport.set_duplicate_delivery(k);
            }
            9 => {
                let s = if splitmix(&mut rng).is_multiple_of(3) {
                    None
                } else {
                    Some(splitmix(&mut rng))
                };
                b.transport.set_reorder_seed(s);
                a.transport.set_reorder_seed(s);
            }
            10 => {
                let up = splitmix(&mut rng).is_multiple_of(2);
                b.transport.set_online(up);
            }
            11 => {
                if splitmix(&mut rng).is_multiple_of(2) {
                    a = w.reopen(a, rcfg(seed));
                } else {
                    b = w.reopen(b, rcfg(seed + 1000));
                }
            }
            12 => {
                let _ = b.node.step_history_sync().await;
            }
            13 => {
                let cap = if splitmix(&mut rng).is_multiple_of(2) {
                    3
                } else {
                    50
                };
                b.transport.set_live_capacity(cap); // small caps overflow and silently drop
            }
            _ => {}
        }
    }
    while sent.len() < n_msgs {
        let id = a.send(&b, &format!("m{}", sent.len())).await.message_id;
        sent.push(id);
    }
    // heal the network, then converge
    for t in [&a.transport, &b.transport] {
        t.set_online(true);
        t.set_duplicate_delivery(1);
        t.set_reorder_seed(None);
        t.set_live_capacity(1000);
    }
    let mut converged = false;
    for _ in 0..400 {
        w.advance(35_000);
        settle(&[&a, &b]).await;
        let _ = b.node.step_history_sync().await;
        let _ = a.node.step_history_sync().await;
        settle(&[&a, &b]).await;
        let mut all = true;
        for id in &sent {
            if a.state(id).await != DeliveryState::Delivered {
                all = false;
                break;
            }
        }
        if all {
            converged = true;
            break;
        }
    }
    assert!(converged, "seed {seed}: did not converge");
    let rows = b.inbox().await;
    let ids: HashSet<_> = rows.iter().map(|r| r.message_id.clone()).collect();
    assert_eq!(rows.len(), n_msgs, "seed {seed}: exactly-once inbox rows");
    assert_eq!(
        ids,
        sent.iter().cloned().collect::<HashSet<_>>(),
        "seed {seed}"
    );
    let evs = b
        .node
        .read_events(PageRequest {
            limit: Some(200),
            ..Default::default()
        })
        .await
        .unwrap()
        .events;
    assert_eq!(
        evs.len(),
        n_msgs,
        "seed {seed}: exactly one event per message"
    );
    assert_eq!(a.n("inbox"), 0, "seed {seed}: acks never land in the inbox");
}

#[tokio::test]
async fn random_schedules_converge_exactly_once() {
    for seed in 0..40 {
        run_seed(seed).await;
    }
}
