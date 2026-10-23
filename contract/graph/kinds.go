// Package graph defines the derived graph vocabulary shared by stores.
package graph

type NodeKind string
type EdgeKind string

const (
	Session     NodeKind = "session"
	Task        NodeKind = "task"
	Checkpoint  NodeKind = "checkpoint"
	Conclusion  NodeKind = "conclusion"
	ToolCall    NodeKind = "tool_call"
	Evidence    NodeKind = "evidence"
	Call        NodeKind = "call"
	Client      NodeKind = "client"
	Machine     NodeKind = "machine"
	Repo        NodeKind = "repo"
	File        NodeKind = "file"
	Commit      NodeKind = "commit"
	Ref         NodeKind = "ref"
	RanOn       EdgeKind = "RAN_ON"
	ByClient    EdgeKind = "BY_CLIENT"
	InRepo      EdgeKind = "IN_REPO"
	AtCommit    EdgeKind = "AT_COMMIT"
	Continues   EdgeKind = "CONTINUES"
	InSession   EdgeKind = "IN_SESSION"
	Captured    EdgeKind = "CAPTURED"
	Read        EdgeKind = "READ"
	Wrote       EdgeKind = "WROTE"
	Ran         EdgeKind = "RAN"
	Cites       EdgeKind = "CITES"
	OfTask      EdgeKind = "OF_TASK"
	FromSession EdgeKind = "FROM_SESSION"
	BoundTo     EdgeKind = "BOUND_TO"
	WorkedOn    EdgeKind = "WORKED_ON"
	SupportedBy EdgeKind = "SUPPORTED_BY"
	ObservedIn  EdgeKind = "OBSERVED_IN"
	Supersedes  EdgeKind = "SUPERSEDES"
	DerivedFrom EdgeKind = "DERIVED_FROM"
	Recalled    EdgeKind = "RECALLED"
	Produced    EdgeKind = "PRODUCED"
	Mentions    EdgeKind = "MENTIONS"
)

func NodeKinds() []NodeKind {
	return []NodeKind{Session, Task, Checkpoint, Conclusion, ToolCall, Evidence, Call, Client, Machine, Repo, File, Commit, Ref}
}
func EdgeKinds() []EdgeKind {
	return []EdgeKind{RanOn, ByClient, InRepo, AtCommit, Continues, InSession, Captured, Read, Wrote, Ran, Cites, OfTask, FromSession, BoundTo, WorkedOn, SupportedBy, ObservedIn, Supersedes, DerivedFrom, Recalled, Produced, Mentions}
}

// LiftAllowed never treats recalled or merely attributed activity as cited support.
func LiftAllowed(edge EdgeKind, basis string, sameRequest bool) bool {
	return edge == SupportedBy && basis == "cited" || edge == FromSession && sameRequest
}
