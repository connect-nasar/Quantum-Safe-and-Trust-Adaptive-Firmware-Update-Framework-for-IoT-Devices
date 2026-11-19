// Witness application adapter for Hyperledger SmartBFT (Apache-2.0).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hyperledger/SmartBFT/pkg/consensus"
	"github.com/hyperledger/SmartBFT/pkg/types"
	"github.com/hyperledger/SmartBFT/pkg/wal"
	pb "github.com/hyperledger/SmartBFT/smartbftprotos"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type Node struct {
	id            uint64
	c             *consensus.Consensus
	bridge, token string
	http          *http.Client
}
type Request struct {
	Command struct {
		Client string `json:"client"`
		ID     string `json:"event_id"`
	} `json:"command"`
}

func (n *Node) rpc(method string, input, output any) error {
	raw, _ := json.Marshal(input)
	req, _ := http.NewRequest("POST", n.bridge+"/rpc/"+method, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+n.token)
	resp, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bridge %s: %s", method, b)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(output)
}
func (n *Node) must(method string, in, out any) {
	if err := n.rpc(method, in, out); err != nil {
		panic(err)
	}
}
func (n *Node) Nodes() []uint64 { return []uint64{1, 2, 3, 4, 5, 6, 7} }
func (n *Node) SendConsensus(id uint64, m *pb.Message) {
	raw, e := proto.Marshal(m)
	if e != nil {
		panic(e)
	}
	var out any
	n.must("send", map[string]any{"target": id, "kind": "consensus", "data": raw}, &out)
}
func (n *Node) SendTransaction(id uint64, r []byte) {
	var out any
	n.must("send", map[string]any{"target": id, "kind": "transaction", "data": r}, &out)
}
func (n *Node) MembershipChange() bool       { return false }
func (n *Node) VerificationSequence() uint64 { return 1 }
func (n *Node) RequestID(raw []byte) types.RequestInfo {
	var r Request
	if json.Unmarshal(raw, &r) != nil {
		return types.RequestInfo{}
	}
	return types.RequestInfo{ClientID: r.Command.Client, ID: r.Command.ID}
}
func (n *Node) VerifyRequest(raw []byte) (types.RequestInfo, error) {
	var out any
	err := n.rpc("verify_request", map[string]any{"raw": raw}, &out)
	return n.RequestID(raw), err
}
func (n *Node) RequestsFromProposal(p types.Proposal) []types.RequestInfo {
	return []types.RequestInfo{n.RequestID(p.Payload)}
}
func (n *Node) AssembleProposal(md []byte, reqs [][]byte) types.Proposal {
	if len(reqs) != 1 {
		panic("one command per proposal")
	}
	return types.Proposal{Header: []byte(os.Getenv("LEDGER_ID")), Payload: reqs[0], Metadata: md, VerificationSequence: 1}
}
func (n *Node) VerifyProposal(p types.Proposal) ([]types.RequestInfo, error) {
	if string(p.Header) != os.Getenv("LEDGER_ID") || p.VerificationSequence != 1 {
		return nil, fmt.Errorf("wrong ledger/suite")
	}
	_, err := n.VerifyRequest(p.Payload)
	return n.RequestsFromProposal(p), err
}
func (n *Node) Sign(raw []byte) []byte {
	var out struct{ Signature []byte }
	n.must("sign", map[string]any{"message": raw}, &out)
	return out.Signature
}
func (n *Node) VerifySignature(s types.Signature) error {
	var out any
	return n.rpc("verify_signature", s, &out)
}

type ProposalMessage struct {
	Digest string
	Aux    []byte
}

func (n *Node) SignProposal(p types.Proposal, aux []byte) *types.Signature {
	msg, _ := json.Marshal(ProposalMessage{p.Digest(), aux})
	return &types.Signature{ID: n.id, Msg: msg, Value: n.Sign(msg)}
}
func (n *Node) VerifyConsenterSig(s types.Signature, p types.Proposal) ([]byte, error) {
	var m ProposalMessage
	if err := json.Unmarshal(s.Msg, &m); err != nil {
		return nil, err
	}
	if m.Digest != p.Digest() {
		return nil, fmt.Errorf("wrong proposal digest")
	}
	return m.Aux, n.VerifySignature(s)
}
func (n *Node) AuxiliaryData(raw []byte) []byte {
	var m ProposalMessage
	_ = json.Unmarshal(raw, &m)
	return m.Aux
}
func (n *Node) Deliver(p types.Proposal, s []types.Signature) types.Reconfig {
	var md pb.ViewMetadata
	if err := proto.Unmarshal(p.Metadata, &md); err != nil {
		panic(err)
	}
	var out any
	n.must("deliver", map[string]any{"decision": types.Decision{Proposal: p, Signatures: s}, "slot": md.LatestSequence, "view": md.ViewId}, &out)
	return types.Reconfig{}
}
func (n *Node) checkDecision(d types.Decision) error {
	if _, err := n.VerifyProposal(d.Proposal); err != nil {
		return err
	}
	seen := map[uint64]bool{}
	for _, s := range d.Signatures {
		if s.ID < 1 || s.ID > 7 || seen[s.ID] {
			return fmt.Errorf("bad proof identity")
		}
		seen[s.ID] = true
		if _, err := n.VerifyConsenterSig(s, d.Proposal); err != nil {
			return err
		}
	}
	if len(seen) < 5 {
		return fmt.Errorf("insufficient commit signatures")
	}
	return nil
}
func (n *Node) Sync() types.SyncResponse {
	for {
		var decisions []types.Decision
		n.must("sync", map[string]any{}, &decisions)
		if len(decisions) == 0 {
			break
		}
		for _, d := range decisions {
			if err := n.checkDecision(d); err != nil {
				panic(err)
			}
			n.Deliver(d.Proposal, d.Signatures)
		}
	}
	var latest types.Decision
	n.must("latest", map[string]any{}, &latest)
	return types.SyncResponse{Latest: latest}
}
func main() {
	id, _ := strconv.ParseUint(os.Getenv("WITNESS_ID"), 10, 64)
	n := &Node{id: id, bridge: os.Getenv("BRIDGE_URL"), token: os.Getenv("BRIDGE_TOKEN"), http: &http.Client{Timeout: 120 * time.Second}}
	logCfg := zap.NewProductionConfig()
	logCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	logger, _ := logCfg.Build()
	defer logger.Sync()
	log := logger.Sugar()
	var latest types.Decision
	n.must("latest", map[string]any{}, &latest)
	var md pb.ViewMetadata
	if len(latest.Proposal.Metadata) > 0 {
		if err := proto.Unmarshal(latest.Proposal.Metadata, &md); err != nil {
			panic(err)
		}
	}
	w, initial, err := wal.InitializeAndReadAll(log, filepath.Join(os.Getenv("DATA_DIR"), "wal"), wal.DefaultOptions())
	if err != nil {
		panic(err)
	}
	cfg := types.DefaultConfig
	cfg.SelfID = id
	cfg.RequestBatchMaxCount = 1
	cfg.RequestMaxBytes = 65536
	cfg.RequestBatchMaxBytes = 65536
	cfg.LeaderRotation = false
	cfg.DecisionsPerLeader = 0
	cfg.LeaderHeartbeatTimeout = 12 * time.Second
	cfg.LeaderHeartbeatCount = 6
	cfg.RequestForwardTimeout = time.Second
	cfg.RequestComplainTimeout = 8 * time.Second
	cfg.ViewChangeResendInterval = 2 * time.Second
	cfg.ViewChangeTimeout = 12 * time.Second
	cfg.SyncOnStart = true
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	vt := time.NewTicker(200 * time.Millisecond)
	defer vt.Stop()
	n.c = &consensus.Consensus{Config: cfg, Application: n, Assembler: n, WAL: w, WALInitialContent: initial, Comm: n, Signer: n, Verifier: n, MembershipNotifier: n, RequestInspector: n, Synchronizer: n, Logger: log, Metadata: &md, LastProposal: latest.Proposal, LastSignatures: latest.Signatures, Scheduler: tick.C, ViewChangerTicker: vt.C}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(wr http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+n.token {
			http.Error(wr, "unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(wr, r.Body, 4<<20)
		wr.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(wr).Encode(map[string]any{"leader": n.c.GetLeaderID()})
		case "/submit":
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				http.Error(wr, e.Error(), 400)
				return
			}
			if _, e = n.VerifyRequest(raw); e == nil {
				e = n.c.SubmitRequest(raw)
			}
			if e != nil {
				http.Error(wr, e.Error(), 400)
				return
			}
			wr.Write([]byte(`{"accepted":true}`))
		case "/message":
			var in struct {
				From uint64
				Kind string
				Data []byte
			}
			if e := json.NewDecoder(r.Body).Decode(&in); e != nil || in.From < 1 || in.From > 7 {
				http.Error(wr, "bad message", 400)
				return
			}
			if in.Kind == "consensus" {
				var m pb.Message
				if e := proto.Unmarshal(in.Data, &m); e != nil {
					http.Error(wr, "bad protobuf", 400)
					return
				}
				n.c.HandleMessage(in.From, &m)
			} else if in.Kind == "transaction" {
				n.c.HandleRequest(in.From, in.Data)
			}
			wr.Write([]byte(`{}`))
		case "/verify_decision":
			var d types.Decision
			if e := json.NewDecoder(r.Body).Decode(&d); e != nil {
				http.Error(wr, "bad proof", 400)
				return
			}
			if e := n.checkDecision(d); e != nil {
				http.Error(wr, e.Error(), 400)
				return
			}
			wr.Write([]byte(`{}`))
		default:
			http.NotFound(wr, r)
		}
	})
	server := &http.Server{Addr: os.Getenv("ENGINE_ADDR"), Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second}
	go func() {
		if e := server.ListenAndServe(); e != nil {
			panic(e)
		}
	}()
	if err := n.c.Start(); err != nil {
		panic(err)
	}
	fmt.Println("SmartBFT engine ready", id, base64.StdEncoding.EncodeToString([]byte("ML-DSA-65")))
	select {}
}
