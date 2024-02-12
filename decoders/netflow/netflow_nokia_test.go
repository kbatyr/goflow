package netflow

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetflowNokia(t *testing.T) {
	f := &FlowMessage{}
	templates := CreateTemplateSystem()

	// no data template
	pkt0 := bytes.NewBuffer(nokiaIPFIXTestPackets[0].Data[42:])
	err := f.Decode(pkt0, templates)
	_, ok := err.(*ErrorTemplateNotFound)
	assert.True(t, ok)

	// data template
	pkt1 := bytes.NewBuffer(nokiaIPFIXTestPackets[1].Data[42:])
	err = f.Decode(pkt1, templates)
	assert.NoError(t, err)

	assert.Equal(t, uint16(10), f.PacketIPFIX.Version)
	assert.Equal(t, uint16(148), f.PacketIPFIX.Length)
	assert.Equal(t, uint32(1114114), f.PacketIPFIX.ObservationDomainId)
	assert.Equal(t, 2, len(f.PacketIPFIX.TemplateFS))

	tempFlowSet0 := f.PacketIPFIX.TemplateFS[0]
	assert.Equal(t, uint16(2), tempFlowSet0.Id)
	assert.Equal(t, uint16(64), tempFlowSet0.Length)
	assert.Equal(t, 11, len(tempFlowSet0.Records[0].Fields))

	const (
		// Vendor-proprietary data field which contains the original IP source address
		// in string type, before NAT is performed.
		// For example: LSN-Host@10.10.10.101
		nokia_aluNatSubString = 93

		// Enterprise number of the vendor.
		pen_nokia = 637
	)

	data := tempFlowSet0.Records[0].Fields[10]
	assert.Equal(t, uint16(nokia_aluNatSubString), data.Type)
	assert.Equal(t, uint32(pen_nokia), data.EnterpriseNumber)

	tempFlowSet1 := f.PacketIPFIX.TemplateFS[1]
	assert.Equal(t, uint16(2), tempFlowSet1.Id)
	assert.Equal(t, uint16(68), tempFlowSet1.Length)
	assert.Equal(t, 12, len(tempFlowSet1.Records[0].Fields))

	data = tempFlowSet1.Records[0].Fields[11]
	assert.Equal(t, uint16(nokia_aluNatSubString), data.Type)
	assert.Equal(t, uint32(pen_nokia), data.EnterpriseNumber)

	// data packet
	pkt2 := bytes.NewBuffer(nokiaIPFIXTestPackets[2].Data[42:])
	err = f.Decode(pkt2, templates)
	assert.NoError(t, err)

	assert.Equal(t, uint16(10), f.PacketIPFIX.Version)
	assert.Equal(t, uint16(1407), f.PacketIPFIX.Length)
	assert.Equal(t, uint32(1008915), f.PacketIPFIX.SequenceNumber)
	assert.Equal(t, uint32(1114114), f.PacketIPFIX.ObservationDomainId)

	assert.Equal(t, 24, len(f.PacketIPFIX.DataFS))

	dataFS0 := f.PacketIPFIX.DataFS[0]
	assert.Equal(t, 1, len(dataFS0.Records))
	assert.Equal(t, uint16(256), dataFS0.Id)
	assert.Equal(t, uint16(60), dataFS0.Length)

	assert.Equal(t, 11, len(dataFS0.Records[0].Values))

	// first record in flow
	flowID := dataFS0.Records[0].Values[0].Value
	assert.Equal(t, []byte{0x14, 0x00, 0x00, 0x00, 0x10, 0x9d, 0xcf, 0x76}, flowID)

	dataFS23 := f.PacketIPFIX.DataFS[23]
	assert.Equal(t, 1, len(dataFS23.Records))
	assert.Equal(t, uint16(256), dataFS23.Id)
	assert.Equal(t, uint16(59), dataFS23.Length)

	// last record in flow
	flowID = dataFS23.Records[0].Values[0].Value
	assert.Equal(t, []byte{0x14, 0x00, 0x00, 0x00, 0xc8, 0xfc, 0xb7, 0x76}, flowID)
}
