#[cfg(test)]
mod tests {
    use crate::store::SynapseStore;
    use crate::episodic::EpisodicMemory;
    use oxigraph::model::*;
    use anyhow::Result;
    use tempfile::tempdir;

    #[test]
    fn test_memory_access_stats() -> Result<()> {
        let dir = tempdir()?;
        let store = SynapseStore::open("test", dir.path().to_str().unwrap())?;

        let uri = "http://synapse.os/memory/1";

        // Initial state: 0 activation
        assert_eq!(store.get_activation(uri), 0.0);

        // Update stats (simulate access)
        store.update_access_stats(uri)?;

        // Should have activation > 0 (frequency=1, recency=0)
        let activation1 = store.get_activation(uri);
        assert!(activation1 > 0.9); // Should be close to 1.0 (freq 1 / (1 + decay*0))

        // Update again (simulate access)
        store.update_access_stats(uri)?;

        // Should have higher activation (frequency=2)
        let activation2 = store.get_activation(uri);
        assert!(activation2 > activation1);
        assert!(activation2 > 1.9); // close to 2.0

        Ok(())
    }

    #[test]
    fn test_episodic_linking() -> Result<()> {
        let dir = tempdir()?;
        let store = SynapseStore::open("test", dir.path().to_str().unwrap())?;

        let ep1 = EpisodicMemory::create_episode(&store.store, "Episode 1", vec![])?;
        let ep2 = EpisodicMemory::create_episode(&store.store, "Episode 2", vec![])?;

        EpisodicMemory::link_episodes(&store.store, &ep1, &ep2)?;

        // Verify link
        let ep1_node = NamedNode::new(&ep1)?;
        let next_pred = NamedNode::new(EpisodicMemory::PRED_NEXT_EPISODE)?;
        let ep2_node = NamedNode::new(&ep2)?;

        assert!(store.store.contains(&Quad::new(
            ep1_node,
            next_pred,
            ep2_node,
            GraphName::DefaultGraph
        ))?);

        Ok(())
    }

    #[test]
    fn test_spreading_activation() -> Result<()> {
        let dir = tempdir()?;
        let store = SynapseStore::open("test", dir.path().to_str().unwrap())?;

        // Graph: A -> B -> C
        let a = "http://synapse.os/A";
        let b = "http://synapse.os/B";
        let c = "http://synapse.os/C";

        // Create nodes and links
        // We use update_access_stats to ensure nodes exist and have baseline activation
        store.update_access_stats(a)?;
        store.update_access_stats(b)?;
        store.update_access_stats(c)?;

        let p = NamedNode::new("http://synapse.os/connectedTo")?;
        let a_node = NamedNode::new(a)?;
        let b_node = NamedNode::new(b)?;
        let c_node = NamedNode::new(c)?;

        store.store.insert(&Quad::new(
            a_node.clone(),
            p.clone(),
            b_node.clone(),
            GraphName::DefaultGraph
        ))?;

        store.store.insert(&Quad::new(
            b_node.clone(),
            p.clone(),
            c_node.clone(),
            GraphName::DefaultGraph
        ))?;

        // Search starting from A
        // Spreading activation should reach B (high) and C (lower)
        let results = store.spreading_activation_search(vec![a.to_string()], 2, 0.5)?;

        // Expected: A (start, highest), B (direct neighbor), C (2 hops)

        let map: std::collections::HashMap<String, f32> = results.into_iter().collect();

        assert!(map.contains_key(a));
        assert!(map.contains_key(b));
        assert!(map.contains_key(c));

        let score_a = *map.get(a).unwrap();
        let score_b = *map.get(b).unwrap();
        let score_c = *map.get(c).unwrap();

        // A is start node, gets reinforcement from self-loop logic in search?
        // Logic: initial activation based on stored stats.
        // A has freq=1. B has freq=1. C has freq=1.
        // Step 1: A spreads to B. B gets (A*0.5) added.
        // Step 2: B spreads to C. C gets (B*0.5) added.

        // So score_b > baseline B. score_c > baseline C.
        // And generally score_b > score_c (closer to source)
        assert!(score_b > 1.0); // Baseline is ~1.0
        assert!(score_c > 1.0);
        // Due to decay, B should receive more from A than C receives from B (if A>B)
        // Here A=1, B=1.
        // B becomes 1 + 0.5 = 1.5.
        // C becomes 1 + (1.5 * 0.5) = 1.75? Wait.
        // Iteration 1: A->B. B=1.5.
        // Iteration 2: B->C. C += 1.5*0.5 = 0.75 -> C=1.75.

        // Wait, spreading activation accumulates.
        // Does it?

        Ok(())
    }
}
