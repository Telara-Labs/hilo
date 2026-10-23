package store

// checkpointVerified captures the same completely verified CURRENT candidate
// against prior exposures, before speculative unreleased exposures are added.
// The sole writer prevents source/auth/fact changes during this lease. Record
// bytes and readonly retained facts are shared; every rebuild-mutated object is
// detached. Spent work and encoding counters remain on Store, outside this copy.
func (d *databaseState) checkpointVerified() (*databaseState, error) {
	c, err := d.reductions()
	if err != nil {
		return nil, err
	}
	if err = c.charge(len(d.records) + len(d.exposures) + len(d.taint) + len(d.taintWitnesses) + len(d.nonces)); err != nil {
		return nil, err
	}
	for _, f := range d.exposures {
		if err = c.charge(len(f.affects)); err != nil {
			return nil, err
		}
	}
	for _, tags := range d.taint {
		if err = c.charge(len(tags)); err != nil {
			return nil, err
		}
	}
	prior := *d
	prior.records = make([]*stored, 0, len(d.records))
	prior.byID = make(map[string]*stored, len(d.byID))
	for _, x := range d.records {
		copy := *x
		prior.records = append(prior.records, &copy)
		prior.byID[x.rec.ID] = &copy
	}
	prior.taint = make(map[string]map[string]bool, len(d.taint))
	for id, tags := range d.taint {
		m := make(map[string]bool, len(tags))
		for tag, v := range tags {
			m[tag] = v
		}
		prior.taint[id] = m
	}
	prior.taintWitnesses = make(map[taintWitness]bool, len(d.taintWitnesses))
	for k, v := range d.taintWitnesses {
		prior.taintWitnesses[k] = v
	}
	prior.nonces = make(map[string]bool, len(d.nonces))
	for k, v := range d.nonces {
		prior.nonces[k] = v
	}
	prior.exposures = make([]*exposureFact, 0, len(d.exposures))
	for _, f := range d.exposures {
		copy := *f
		copy.affects = make(map[string]bool, len(f.affects))
		for id, v := range f.affects {
			copy.affects[id] = v
		}
		prior.exposures = append(prior.exposures, &copy)
	}
	// Grouped observations contain immutable Record pointers and prior status
	// values. Rebuild replaces the group pointer before mutating current state.
	return &prior, nil
}
func (d *databaseState) restoreVerified(prior *databaseState) {
	spentNonceLookups := d.nonceLookups
	*d = *prior
	d.nonceLookups = max(d.nonceLookups, spentNonceLookups)
}
