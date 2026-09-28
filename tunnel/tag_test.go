package tunnel

import "testing"

func TestRoutingAuthentication(t *testing.T) {
	for _, request := range []routingRequest{{tagVersion, "A"}, {targetVersion, "127.0.0.1:9001"}} {
		t.Run(request.destination, func(t *testing.T) {
			server, client := NewTaa("shared"), NewTaa("shared")
			server.GenToken()
			response, ok := client.ExchangeCipherBlock(server.GenCipherBlock(nil))
			if !ok {
				t.Fatal("challenge exchange failed")
			}
			routed := client.routingResponse(response, request)
			defer mpool.Put(routed)
			if got, err := server.verifyRoutingResponse(routed); err != nil || got != request {
				t.Fatalf("request=%v err=%v", got, err)
			}
			ack := server.routingAck(request, routeAccepted)
			defer mpool.Put(ack)
			if err := client.verifyRoutingAck(request, ack); err != nil {
				t.Fatal(err)
			}
			routed[TaaBlockSize+1]++
			if _, err := server.verifyRoutingResponse(routed); err == nil {
				t.Fatal("accepted a modified destination")
			}
			routed[TaaBlockSize+1]--
			routed[TaaBlockSize] = 3
			if _, err := server.verifyRoutingResponse(routed); err == nil {
				t.Fatal("accepted an unsupported routing version")
			}
			ack[1] = tagUnknown
			if err := client.verifyRoutingAck(request, ack); err == nil {
				t.Fatal("accepted a modified acknowledgement")
			}
			if _, err := server.verifyRoutingResponse(response); err == nil {
				t.Fatal("accepted a legacy response in routing mode")
			}
		})
	}
}
