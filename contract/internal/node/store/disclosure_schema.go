package store

import "context"

const disclosureSchema = `
CREATE TABLE IF NOT EXISTS operation_token(token TEXT PRIMARY KEY,credential TEXT NOT NULL REFERENCES client_credential(id),consumed INTEGER NOT NULL CHECK(consumed IN(0,1)));
CREATE TABLE IF NOT EXISTS outcome_lookup(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,record_kind TEXT NOT NULL,include_content INTEGER NOT NULL CHECK(include_content IN(0,1)),PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS disclosure_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL CHECK(version=2));
CREATE TABLE IF NOT EXISTS projection_hold(owner TEXT PRIMARY KEY,machine TEXT NOT NULL,reason TEXT NOT NULL CHECK(reason='lineage_evaluation_required'),generation INTEGER NOT NULL CHECK(generation>=0));
CREATE TABLE IF NOT EXISTS client_credential(id TEXT PRIMARY KEY CHECK(length(id)=36),owner TEXT NOT NULL,machine TEXT NOT NULL,name TEXT NOT NULL,verifier BLOB,epoch INTEGER NOT NULL CHECK(epoch>0),revoked INTEGER NOT NULL CHECK(revoked IN(0,1)),read_repo_kind TEXT NOT NULL CHECK(read_repo_kind IN('deny','all-local','concrete')),write_repo_kind TEXT NOT NULL CHECK(write_repo_kind IN('deny','all-local','concrete')),allow_unscoped INTEGER NOT NULL CHECK(allow_unscoped IN(0,1)),CHECK(allow_unscoped=0 OR write_repo_kind='all-local'));
CREATE TABLE IF NOT EXISTS client_grant_repo(credential TEXT NOT NULL REFERENCES client_credential(id),repo TEXT NOT NULL CHECK(length(repo) IN(67,68)),PRIMARY KEY(credential,repo));
CREATE TABLE IF NOT EXISTS client_grant_channel(credential TEXT NOT NULL REFERENCES client_credential(id),channel TEXT NOT NULL CHECK(channel IN('S','P','E')),PRIMARY KEY(credential,channel));
CREATE TABLE IF NOT EXISTS client_task_write(credential TEXT NOT NULL REFERENCES client_credential(id),action TEXT NOT NULL CHECK(action IN('create','checkpoint','pause','complete')),PRIMARY KEY(credential,action));
CREATE TABLE IF NOT EXISTS client_task_write_repo(credential TEXT NOT NULL REFERENCES client_credential(id),repo TEXT NOT NULL CHECK(length(repo) IN(67,68)),PRIMARY KEY(credential,repo));
CREATE TABLE IF NOT EXISTS admin_outcome(owner TEXT NOT NULL,machine TEXT NOT NULL,key_id TEXT NOT NULL,op TEXT NOT NULL,command TEXT NOT NULL,args_hash TEXT NOT NULL,credential TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(owner,machine,key_id,op));
CREATE TABLE IF NOT EXISTS local_scope(id TEXT PRIMARY KEY,owner TEXT NOT NULL,machine TEXT NOT NULL,credential TEXT NOT NULL REFERENCES client_credential(id),identity_kind TEXT NOT NULL,handle_key TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),evidence INTEGER NOT NULL CHECK(evidence>=0),repo_state TEXT NOT NULL CHECK(repo_state IN('unknown','known','explicitly_unscoped')),repo TEXT NOT NULL,native_session TEXT NOT NULL,UNIQUE(credential,identity_kind,handle_key));
CREATE TABLE IF NOT EXISTS record_attribution(id TEXT PRIMARY KEY REFERENCES record(id),owner TEXT NOT NULL,machine TEXT NOT NULL,scope TEXT NOT NULL,kind TEXT NOT NULL,repo_state TEXT NOT NULL,repo TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_write_scope(owner TEXT NOT NULL,task TEXT NOT NULL,repo_state TEXT NOT NULL,repo TEXT NOT NULL,credential TEXT NOT NULL,creation_op TEXT NOT NULL,evidence INTEGER NOT NULL,PRIMARY KEY(owner,task));
CREATE TABLE IF NOT EXISTS operation(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,tool TEXT NOT NULL,args_hash TEXT NOT NULL,call_ref TEXT NOT NULL,call_id TEXT NOT NULL,arg_schema TEXT NOT NULL,ruleset TEXT NOT NULL,builder TEXT NOT NULL,outcome_schema TEXT NOT NULL,kind TEXT NOT NULL,renderer TEXT NOT NULL,retrieval TEXT NOT NULL,selected INTEGER NOT NULL CHECK(selected>=0),total INTEGER,result TEXT NOT NULL,is_error INTEGER NOT NULL CHECK(is_error IN(0,1)),created_seq INTEGER NOT NULL,scope TEXT NOT NULL,grant_epoch INTEGER NOT NULL,scope_generation INTEGER NOT NULL,evidence INTEGER NOT NULL,db_generation INTEGER NOT NULL,max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 2048 AND 262144),PRIMARY KEY(owner,credential,op),UNIQUE(owner,call_ref));
CREATE TABLE IF NOT EXISTS outcome_member(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 127),role TEXT NOT NULL,required INTEGER NOT NULL CHECK(required IN(0,1)),record_owner TEXT NOT NULL,id TEXT NOT NULL,task TEXT NOT NULL,presentation TEXT NOT NULL CHECK(presentation IN('fresh_projection','quoted_source')),PRIMARY KEY(owner,credential,op,ordinal),FOREIGN KEY(owner,credential,op) REFERENCES operation(owner,credential,op));
CREATE TABLE IF NOT EXISTS outcome_dependency(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,member INTEGER NOT NULL,id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(owner,credential,op,member,id,role));
CREATE TABLE IF NOT EXISTS outcome_warning(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,ordinal INTEGER NOT NULL,code TEXT NOT NULL,PRIMARY KEY(owner,credential,op,ordinal));
CREATE TABLE IF NOT EXISTS outcome_filter(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,include_completed INTEGER NOT NULL CHECK(include_completed IN(0,1)),query_required INTEGER NOT NULL CHECK(query_required IN(0,1)),PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS outcome_query(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,query TEXT NOT NULL CHECK(length(query)<=1000),PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS outcome_task(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,task_owner TEXT NOT NULL,task TEXT NOT NULL,action TEXT NOT NULL,PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS outcome_page(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,selection TEXT NOT NULL,start_offset INTEGER NOT NULL,end_offset INTEGER NOT NULL,universe_known INTEGER NOT NULL,PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS outcome_continuation(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,cursor TEXT NOT NULL,selection TEXT NOT NULL,next_offset INTEGER NOT NULL,PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS exposure(id TEXT PRIMARY KEY,owner TEXT NOT NULL,machine TEXT NOT NULL,credential TEXT NOT NULL,scope TEXT NOT NULL,root TEXT NOT NULL,source_call TEXT NOT NULL,attempt TEXT NOT NULL,fence INTEGER NOT NULL CHECK(fence>=0),predicate TEXT NOT NULL CHECK(predicate='local-admission-fence/1'));
CREATE TABLE IF NOT EXISTS exposure_affect(exposure TEXT NOT NULL REFERENCES exposure(id),target TEXT NOT NULL,PRIMARY KEY(exposure,target));
CREATE TABLE IF NOT EXISTS exposure_evidence(exposure TEXT NOT NULL REFERENCES exposure(id),evidence TEXT NOT NULL,PRIMARY KEY(exposure,evidence));
CREATE TABLE IF NOT EXISTS semantic_hold_cause(owner TEXT NOT NULL,target TEXT NOT NULL,root TEXT NOT NULL,control TEXT NOT NULL,PRIMARY KEY(owner,target,root,control));
CREATE TABLE IF NOT EXISTS record_observed_taint(owner TEXT NOT NULL,id TEXT NOT NULL,tag TEXT NOT NULL CHECK(tag IN('web','third-party-mcp','foreign-path','recalled-memory')),PRIMARY KEY(owner,id,tag));
CREATE TABLE IF NOT EXISTS record_taint_evidence(owner TEXT NOT NULL,id TEXT NOT NULL,tag TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('header_claim','session_boundary','dependency','binding_projection','possible_recall_field')),evidence TEXT NOT NULL,source TEXT NOT NULL,boundary TEXT NOT NULL,PRIMARY KEY(owner,id,tag,kind,evidence,source,boundary));
CREATE TABLE IF NOT EXISTS field_completeness(owner TEXT NOT NULL,id TEXT NOT NULL,event TEXT NOT NULL,revision TEXT NOT NULL,family TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 4095),instance TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,source_kind TEXT NOT NULL CHECK(source_kind IN('mcp_argument','mcp_generated','mcp_generated_name_from_goal')),source_slot TEXT NOT NULL,source_ordinal INTEGER NOT NULL CHECK(source_ordinal BETWEEN 0 AND 255),builder TEXT NOT NULL,arg_schema TEXT NOT NULL,ruleset TEXT NOT NULL,full_bytes INTEGER NOT NULL CHECK(full_bytes>=0),retained_bytes INTEGER NOT NULL CHECK(retained_bytes>=0),PRIMARY KEY(owner,id,event,revision,family,ordinal));
CREATE TABLE IF NOT EXISTS record_field_projection(owner TEXT NOT NULL,id TEXT NOT NULL,event TEXT NOT NULL,revision TEXT NOT NULL,family TEXT NOT NULL,ordinal INTEGER NOT NULL,classifier TEXT NOT NULL,class TEXT NOT NULL CHECK(class IN('no_detected_marker','injected_source','possible_memory_frame','classification_unavailable')),reason TEXT NOT NULL,PRIMARY KEY(owner,id,event,revision,family,ordinal));
CREATE TABLE IF NOT EXISTS render_attempt(id TEXT PRIMARY KEY,owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,scope TEXT NOT NULL,original_generation INTEGER NOT NULL,nonce TEXT NOT NULL CHECK(length(nonce)=20),version TEXT NOT NULL,db_generation INTEGER NOT NULL,grant_epoch INTEGER NOT NULL,evidence INTEGER NOT NULL,released INTEGER NOT NULL,UNIQUE(owner,nonce));
CREATE TABLE IF NOT EXISTS render_item(attempt TEXT NOT NULL REFERENCES render_attempt(id),ordinal INTEGER NOT NULL,owner TEXT NOT NULL,lid TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(attempt,ordinal),UNIQUE(attempt,lid,id));
CREATE TABLE IF NOT EXISTS render_dep(attempt TEXT NOT NULL REFERENCES render_attempt(id),id TEXT NOT NULL,PRIMARY KEY(attempt,id));
CREATE TABLE IF NOT EXISTS render_body(attempt TEXT PRIMARY KEY REFERENCES render_attempt(id),text BLOB NOT NULL CHECK(length(text)<=262144));
CREATE TABLE IF NOT EXISTS render_warning(attempt TEXT NOT NULL,ordinal INTEGER NOT NULL,code TEXT NOT NULL,PRIMARY KEY(attempt,ordinal));
CREATE TABLE IF NOT EXISTS render_empty_result(attempt TEXT PRIMARY KEY,code TEXT NOT NULL CHECK(code IN('query_required','recorded_empty_selection')));
CREATE TABLE IF NOT EXISTS render_visible_counts(attempt TEXT PRIMARY KEY,shown_roots INTEGER NOT NULL,shown_units INTEGER NOT NULL,omitted_records INTEGER NOT NULL,original_state TEXT NOT NULL,total INTEGER);
CREATE TABLE IF NOT EXISTS attempt_ack(attempt TEXT PRIMARY KEY REFERENCES render_attempt(id));
CREATE TABLE IF NOT EXISTS synthetic_compaction_signal(id TEXT PRIMARY KEY,scope TEXT NOT NULL REFERENCES local_scope(id),generation INTEGER NOT NULL CHECK(generation>0),kind TEXT NOT NULL CHECK(kind='owner-fixture'),consumed INTEGER NOT NULL CHECK(consumed IN(0,1)));
CREATE TABLE IF NOT EXISTS delivery_confirmation(credential TEXT NOT NULL,scope TEXT NOT NULL,generation INTEGER NOT NULL,lid TEXT NOT NULL,id TEXT NOT NULL,attempt TEXT NOT NULL,PRIMARY KEY(credential,scope,generation,lid,id));
CREATE TABLE IF NOT EXISTS projection_count_snapshot(id TEXT PRIMARY KEY,owner TEXT NOT NULL,credential TEXT NOT NULL,scope_key TEXT NOT NULL,channel TEXT NOT NULL,filter_version TEXT NOT NULL,projection_version TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('known','unknown','not_requested')),reason TEXT,records INTEGER,total INTEGER,searchable INTEGER,excluded INTEGER,unclassified INTEGER,records_excluded INTEGER,CHECK((state='known' AND reason IS NULL AND records IS NOT NULL AND total IS NOT NULL AND searchable IS NOT NULL AND excluded IS NOT NULL AND unclassified IS NOT NULL AND records_excluded IS NOT NULL AND records<=8192 AND total<=65536 AND searchable<=65536 AND excluded<=65536 AND unclassified<=65536 AND records_excluded<=8192 AND records>=0 AND total>=0 AND searchable>=0 AND excluded>=0 AND unclassified>=0 AND records_excluded>=0 AND total=searchable+excluded+unclassified) OR (state='unknown' AND reason IS NOT NULL AND reason IN('count_record_limit','count_body_limit','count_unit_limit') AND records IS NULL AND total IS NULL AND searchable IS NULL AND excluded IS NULL AND unclassified IS NULL AND records_excluded IS NULL) OR (state='not_requested' AND reason IS NULL AND records IS NULL AND total IS NULL AND searchable IS NULL AND excluded IS NULL AND unclassified IS NULL AND records_excluded IS NULL)));
CREATE TABLE IF NOT EXISTS outcome_projection_summary(owner TEXT NOT NULL,credential TEXT NOT NULL,op TEXT NOT NULL,snapshot TEXT NOT NULL,PRIMARY KEY(owner,credential,op));
CREATE TABLE IF NOT EXISTS render_projection_summary(attempt TEXT PRIMARY KEY,snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS query_selection(id TEXT PRIMARY KEY,credential TEXT NOT NULL,scope TEXT NOT NULL,generation INTEGER NOT NULL,grant_epoch INTEGER NOT NULL,query_hash TEXT NOT NULL,ordering TEXT NOT NULL,engine TEXT NOT NULL,candidate_count INTEGER NOT NULL CHECK(candidate_count BETWEEN 0 AND 300),universe_known INTEGER NOT NULL,evidence INTEGER NOT NULL CHECK(evidence>=0));
CREATE TABLE IF NOT EXISTS selection_item(selection TEXT NOT NULL,ordinal INTEGER NOT NULL,id TEXT NOT NULL,PRIMARY KEY(selection,ordinal));
CREATE TABLE IF NOT EXISTS selection_payload(selection TEXT PRIMARY KEY,query TEXT NOT NULL,resource_types TEXT NOT NULL,page_size INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS query_cursor(id TEXT PRIMARY KEY,selection TEXT NOT NULL,offset INTEGER NOT NULL,expected_generation INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('ready','consumed','expired')),consumed_by TEXT NOT NULL);
`

func (s *Store) initializeDisclosure(ctx context.Context) error {
	if _, err := s.conn.ExecContext(ctx, disclosureSchema); err != nil {
		return failure("storage_error")
	}
	if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO disclosure_meta VALUES(1,2)"); err != nil {
		return failure("storage_error")
	}
	var version int
	if s.conn.QueryRowContext(ctx, "SELECT version FROM disclosure_meta WHERE singleton=1").Scan(&version) != nil || version != 2 {
		return failure("incompatible_database")
	}
	// A new store incarnation has no live old transport. Ephemeral scopes are
	// never retry identity across that boundary; retain historical op/exposure IDs.
	for _, q := range []string{"DELETE FROM synthetic_compaction_signal WHERE scope IN(SELECT id FROM local_scope WHERE identity_kind='connection')", "DELETE FROM local_scope WHERE identity_kind='connection'"} {
		if _, err := s.conn.ExecContext(ctx, q); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
