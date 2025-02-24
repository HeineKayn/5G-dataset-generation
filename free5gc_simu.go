package test_test

import (
	"bytes"
	"context"

	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"test"
	"test/consumerTestdata/PCF/TestPolicyAuthorization"
	"test/consumerTestdata/UDM/TestGenAuthData"
	"test/nasTestpacket"

	"github.com/free5gc/sctp"
	"github.com/gin-gonic/gin"
	"github.com/mohae/deepcopy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/Npcf_PolicyAuthorization"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	"github.com/free5gc/util/milenage"
)

const ranN2Ipv4Addr string = "127.0.0.1"
const amfN2Ipv4Addr string = "127.0.0.1"
const amfN2Ipv4Addr2 string = "127.0.0.50"
const ranN3Ipv4Addr string = "10.200.200.1"
const upfN3Ipv4Addr string = "10.200.200.102"

func recvUeConfigUpdateCmd(t *testing.T, recvMsg []byte, conn *sctp.SCTPConn) {
	n, err := conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.Present, ngapType.NGAPPDUPresentInitiatingMessage, "Not NGAPPDUPresentInitiatingMessage")
	assert.Equal(t, ngapPdu.InitiatingMessage.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkNASTransport,
		"Not ProcedureCodeDownlinkNASTransport")
}

// Registration
func TestRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	servingPlmnId := "20893"

	// insert UE data to MongoDB
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(100 * time.Millisecond)

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.60.0.1").To4(),
		Dst:      net.ParseIP("10.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> DeRegistration(UE Originating)
func TestDeregistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	servingPlmnId := "20893"

	// insert UE data to MongoDB
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(500 * time.Millisecond)

	// send NAS Deregistration Request (UE Originating)
	mobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	pdu = nasTestpacket.GetDeregistrationRequest(nasMessage.AccessType3GPP, 0, 0x04, mobileIdentity5GS)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	// receive Deregistration Accept
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeDownlinkNASTransport,
		"No DownlinkNASTransport received.")
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu, "NAS PDU is nil")
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration,
		"Received wrong GMM message. Expected Deregistration Accept.")

	// receive ngap UE Context Release Command
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease,
		"No UEContextReleaseCommand received.")

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> Pdu Session Establishment -> AN Release due to UE Idle -> UE trigger Service Request Procedure
func TestServiceRequest(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	servingPlmnId := "20893"

	// insert UE data to MongoDB
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// UE is CM-IDLE now
	time.Sleep(1 * time.Second)

	ue.AmfUeNgapId = 2
	// send NAS Service Request
	pdu = nasTestpacket.GetServiceRequest(nasMessage.ServiceTypeData)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive Initial Context Setup Request
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// update AMF UE NGAP ID
	require.NotNil(t, ngapMsg.InitiatingMessage.Value.InitialContextSetupRequest)
	ue.AmfUeNgapId = ngapMsg.InitiatingMessage.
		Value.InitialContextSetupRequest.ProtocolIEs.List[0].Value.AMFUENGAPID.Value

	// Send Initial Context Setup Response
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> DeRegistration(UE Originating)
func TestGUTIRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	require.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	servingPlmnId := "20893"

	// insert UE data to MongoDB
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	SUCI5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, SUCI5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		SUCI5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(500 * time.Millisecond)

	// send NAS Deregistration Request (UE Originating)
	GUTI5GS := nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	pdu = nasTestpacket.GetDeregistrationRequest(nasMessage.AccessType3GPP, 0, 0x04, GUTI5GS)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	// receive NAS Deregistration Accept
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration,
		"Received wrong GMM message. Expected Deregistration Accept.")

	// receive ngap UE Context Release Command
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(200 * time.Millisecond)

	// ========================= Second Registration - Register with GUTI =========================

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	// innerRegistrationRequest will be encapsulated in the registrationRequest
	ue.AmfUeNgapId = 2
	innerRegistrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	registrationRequest = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ueSecurityCapability, nil, innerRegistrationRequest, nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, true)
	require.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "")
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Identity Request
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeIdentityRequest,
		"Received wrong GMM message. Expected Identity Request.")

	// update AMF UE NGAP ID
	ue.AmfUeNgapId = ngapMsg.InitiatingMessage.
		Value.DownlinkNASTransport.
		ProtocolIEs.List[0].Value.AMFUENGAPID.Value

	// send NAS Identity Response
	mobileIdentity := nasType.MobileIdentity{
		Len:    SUCI5GS.Len,
		Buffer: SUCI5GS.Buffer,
	}
	pdu = nasTestpacket.GetIdentityResponse(mobileIdentity)
	require.Nil(t, err)

	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")

	// Calculate for RES*
	rand = nasPdu.AuthenticationRequest.GetRANDValue()
	sqn, _ := strconv.ParseUint(ue.AuthenticationSubs.SequenceNumber, 16, 48)
	sqn++
	ue.AuthenticationSubs.SequenceNumber = strconv.FormatUint(sqn, 16)
	resStat = ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu = nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	pdu = nasTestpacket.GetSecurityModeComplete(innerRegistrationRequest)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	require.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(1000 * time.Millisecond)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> Pdu Session Establishment -> Pdu Session Release
func TestPDUSessionReleaseRequest(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	servingPlmnId := "20893"

	// insert UE data to MongoDB
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// Send Pdu Session Establishment Release Request
	pdu = nasTestpacket.GetUlNasTransport_PduSessionReleaseRequest(10)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1000 * time.Millisecond)
	// send N2 Resource Release Ack(PDUSession Resource Release Response)
	sendMsg, err = test.GetPDUSessionResourceReleaseResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 10 ms
	time.Sleep(1000 * time.Millisecond)

	//send N1 PDU Session Release Ack PDU session release complete
	pdu = nasTestpacket.GetUlNasTransport_PduSessionReleaseComplete(10, nasMessage.ULNASTransportRequestTypeExistingPduSession, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait result
	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestPDUSessionReleaseAbnormal(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// Send Pdu Session Release Request
	pdu = nasTestpacket.GetUlNasTransport_PduSessionReleaseRequest(10)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive PDU Session Resource Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(1000 * time.Millisecond)
	// send N2 Resource Release Ack(PDUSession Resource Release Response)
	sendMsg, err = test.GetPDUSessionResourceReleaseResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// Just test registration no occur panic
	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait result
	time.Sleep(2 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> Pdu Session Establishment -> Path Switch(Xn Handover)
func TestXnHandover(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x01"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	conn2, err1 := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9488)
	assert.Nil(t, err1)

	// send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(2000 * time.Millisecond)
	// send Path Switch Request (XnHandover)
	sendMsg, err = test.GetPathSwitchRequest(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive Path Switch Request (XnHandover)
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()
	conn2.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> Pdu Session Establishment -> AN Release due to UE Idle -> Send downlink data
func TestPaging(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMFcd
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// UE is CM-IDLE now

	time.Sleep(1 * time.Second)

	// send downlink data
	go func() {
		// RAN connect to UPF
		upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
		_, _ = upfConn.Read(recvMsg)
		// fmt.Println(string(recvMsg))
	}()

	cmd := exec.Command("sudo", "ip", "netns", "exec", "UPFns", "bash", "-c", "echo -n 'hello' | nc -u -w1 10.60.0.1 8080")
	_, err = cmd.Output()
	if err != nil {
		fmt.Println(err)
		assert.Nil(t, err)
	}

	time.Sleep(1 * time.Second)

	// receive paing
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	ue.AmfUeNgapId = 2
	// send NAS Service Request
	pdu = nasTestpacket.GetServiceRequest(nasMessage.ServiceTypeMobileTerminatedServices)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive Initial Context Setup Request
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// update AMF UE NGAP ID
	ue.AmfUeNgapId = ngapMsg.InitiatingMessage.
		Value.InitialContextSetupRequest.ProtocolIEs.List[0].Value.AMFUENGAPID.Value

	//send Initial Context Setup Response
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

// Registration -> PDU Session Establishment -> Source RAN Send Handover Required -> N2 Handover (Preparation Phase -> Execution Phase)
func TestN2Handover(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN1 connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN1 connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
	assert.Nil(t, err)

	// RAN1 send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x01"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// RAN1 receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// RAN2 connect to AMF
	conn2, err1 := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9488)
	assert.Nil(t, err1)

	// RAN2 connect to UPF
	upfConn2, err := test.ConnectToUpf("10.200.200.2", "10.200.200.102", 2152, 2152)
	assert.Nil(t, err)

	// RAN2 send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// RAN2 receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// Send the dummy packet to test if UE is connected to RAN1
	// ping IP(tunnel IP) from 10.60.0.1(127.0.0.1) to 10.60.0.100(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.60.0.1").To4(),
		Dst:      net.ParseIP("10.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)
	assert.Nil(t, err)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// ============================================

	// Source RAN send ngap Handover Required Msg
	sendMsg, err = test.GetHandoverRequired(ue.AmfUeNgapId, ue.RanUeNgapId, []byte{0x00, 0x01, 0x02}, []byte{0x01, 0x20})
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// Target RAN receive ngap Handover Request
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN create New UE
	targetUe := deepcopy.Copy(ue).(*test.RanUeContext)
	targetUe.AmfUeNgapId = 2
	targetUe.ULCount.Set(ue.ULCount.Overflow(), ue.ULCount.SQN())
	targetUe.DLCount.Set(ue.DLCount.Overflow(), ue.DLCount.SQN())

	// Target RAN send ngap Handover Request Acknowledge Msg
	sendMsg, err = test.GetHandoverRequestAcknowledge(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// End of Preparation phase
	time.Sleep(10 * time.Millisecond)

	// Beginning of Execution

	// Source RAN receive ngap Handover Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Handover Notify
	sendMsg, err = test.GetHandoverNotify(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// Source RAN receive ngap UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Source RAN send ngap UE Context Release Complete
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// UE send NAS Registration Request(Mobility Registration Update) To Target AMF (2 AMF scenario not supportted yet)
	mobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	uplinkDataStatus := nasType.NewUplinkDataStatus(nasMessage.RegistrationRequestUplinkDataStatusType)
	uplinkDataStatus.SetLen(2)
	uplinkDataStatus.SetPSI10(1)
	ueSecurityCapability = targetUe.GetUESecurityCapability()
	pdu = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, uplinkDataStatus)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// Target RAN receive ngap Initial Context Setup Request Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetPDUSessionResourceSetupResponseForPaging(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, "10.200.200.2")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// Target RAN send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn2)

	// wait 1000 ms
	time.Sleep(1000 * time.Millisecond)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	_, err = upfConn2.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()
	conn2.Close()

	// terminate all NF
	NfTerminate()
}

func TestDuplicateRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA0, models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(100 * time.Millisecond)

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	PduSessionEstablishmentRequestMSG, err := test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(PduSessionEstablishmentRequestMSG)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	//send PduSessionEstablishment Request Msg again to make error

	_, err = conn.Write(PduSessionEstablishmentRequestMSG)
	assert.Nil(t, err)

	sendMsg, err = test.GetPDUSessionResourceReleaseResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000300000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.60.0.2").To4(),
		Dst:      net.ParseIP("10.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)
	assert.Nil(t, err)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestAFInfluenceOnTrafficRouting(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// fake AF
	go func() {
		router := gin.Default()
		router.POST("nnef-callback/v1/traffic-influence/:appID", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		router.POST("nnef-callback/v1/applications/:appID/terminate", func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		})

		server, err := httpwrapper.NewHttp2Server("127.0.0.100:8000", "", router)
		if err == nil && server != nil {
			err = server.ListenAndServe()
		}
		assert.True(t, err == nil)
	}()

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA0, models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(100 * time.Millisecond)

	// send GetPduSessionEstablishmentRequest Msg
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet",
		&models.Snssai{Sst: 1, Sd: "fedcba"})
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet

	cfg := Npcf_PolicyAuthorization.NewConfiguration()
	cfg.SetBasePath("http://127.0.0.7:8000")
	client := Npcf_PolicyAuthorization.NewAPIClient(cfg)

	appSessCtx := TestPolicyAuthorization.GetPostAppSessionsData_AFInfluenceOnTrafficRouting()

	_, _, err = client.ApplicationSessionsCollectionApi.PostAppSessions(context.Background(), appSessCtx)
	assert.Nil(t, err, "PolicyAuthorize failed")

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestReSynchronization(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")

	// gen AK
	K, OPC := make([]byte, 16), make([]byte, 16)
	K, _ = hex.DecodeString(ue.AuthenticationSubs.PermanentKey.PermanentKeyValue)
	OPC, _ = hex.DecodeString(ue.AuthenticationSubs.Opc.OpcValue)
	SQN := make([]byte, 6)
	AK := make([]byte, 6)

	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	milenage.F2345(OPC, K, rand[:], nil, nil, nil, AK, nil)
	autn := nasPdu.AuthenticationRequest.GetAUTN()
	SQNxorAK := autn[:6]
	for i := 0; i < 6; i++ {
		SQN[i] = AK[i] ^ SQNxorAK[i]
	}
	const SqnMAx int64 = 0x7FFFFFFFFFF
	const SqnMs int64 = 0
	const IND int64 = 32
	var newSqnMsString string
	SQNBuffer := make([]byte, 8)
	copy(SQNBuffer[2:], SQN)
	r := bytes.NewReader(SQNBuffer)
	var retrieveSqn int64
	if err := binary.Read(r, binary.BigEndian, &retrieveSqn); err != nil {
		fmt.Println("err", err)
		return
	}

	delita := retrieveSqn - SqnMs
	if delita < 0x7FFFFFFFFFF {
		newSqnMsString = "000000000000"
	}

	newSqnMs, _ := hex.DecodeString(newSqnMsString)
	MAC_A, MAC_S := make([]byte, 8), make([]byte, 8)
	CK, IK := make([]byte, 16), make([]byte, 16)
	RES := make([]byte, 8)
	AK, AKstar := make([]byte, 6), make([]byte, 6)
	AMF, _ := hex.DecodeString("0000")
	milenage.F1(OPC, K, rand[:], newSqnMs, AMF, MAC_A, MAC_S)
	milenage.F2345(OPC, K, rand[:], RES, CK, IK, AK, AKstar)

	SQNmsxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}
	ColSQNmsxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		ColSQNmsxorAK[i] = SQNmsxorAK[i] ^ AKstar[i]
	}
	AUTS := append(ColSQNmsxorAK, MAC_S...)
	// compute SQN by AUTN, K, AK
	// suppose
	// send NAS Authentication Rejcet
	// failureParam := []uint8{0x68, 0x58, 0x15, 0x86, 0x1f, 0xec, 0x0f, 0xa9, 0x48, 0xe8, 0xb2, 0x3a, 0x08, 0x62}
	failureParam := AUTS
	pdu := nasTestpacket.GetAuthenticationFailure(nasMessage.Cause5GMMSynchFailure, failureParam)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu = test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand = nasPdu.AuthenticationRequest.GetRANDValue()

	milenage.F2345(OPC, K, rand[:], nil, nil, nil, AK, nil)
	autn = nasPdu.AuthenticationRequest.GetAUTN()
	SQNxorAK = autn[:6]

	for i := 0; i < 6; i++ {
		SQN[i] = AK[i] ^ SQNxorAK[i]
	}
	fmt.Printf("retrieve SQN %x\n", SQN)
	ue.AuthenticationSubs.SequenceNumber = hex.EncodeToString(SQN)
	resStar := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu = nasTestpacket.GetAuthenticationResponse(resStar, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	time.Sleep(100 * time.Millisecond)

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.60.0.1").To4(),
		Dst:      net.ParseIP("10.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)
	assert.Nil(t, err)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestRequestTwoPDUSessions(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.101", 3001, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	sNssai = models.Snssai{
		Sst: 1,
		Sd:  "112233",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(11, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet2", &sNssai)

	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(11, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	udpServer := ranN3Ipv4Addr + ":2152"
	udpListener, err := net.ListenPacket("udp", udpServer)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer udpListener.Close()

	fmt.Printf("UDP server start and listening on %s.\n", udpServer)
	go func() {
		for {
			buf := make([]byte, 1024)
			_, _, err := udpListener.ReadFrom(buf)
			if err != nil {
				continue
			}
		}
	}()

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.60.0.1").To4(),
		Dst:      net.ParseIP("10.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	upfConn2, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 3002, 2152)
	assert.Nil(t, err, err)
	//
	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	gtpHdr, err = hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err = hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr = ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("10.62.0.1").To4(),
		Dst:      net.ParseIP("10.60.0.102").To4(),
		ID:       1,
	}
	checksum = test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err = ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt = append(gtpHdr, v4HdrBuf...)

	m = icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err = m.Marshal(nil)

	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn2.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestEAPAKAPrimeAuthentication(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetEAPAKAPrimeAuthSubscription(
		TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for Response EAPMessage
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	eAPMessage := nasPdu.AuthenticationRequest.GetEAPMessage()
	resEAPMessage := ue.DeriveResEAPMessageAndSetKey(ue.AuthenticationSubs, eAPMessage, "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(nil, base64.StdEncoding.EncodeToString(resEAPMessage))
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, conn)

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("60.60.0.1").To4(),
		Dst:      net.ParseIP("60.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

func TestMultiAmfRegistration(t *testing.T) {
	time.Sleep(3 * time.Second)

	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to old amf
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// RAN connect to new amf
	conn2, err := test.ConnectToAmf(amfN2Ipv4Addr2, ranN2Ipv4Addr, 38413, 9488)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	var guti *nasType.GUTI5G
	for _, ie := range ngapPdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDNASPDU {
			payload := []byte(ie.Value.NASPDU.Value)
			m, err := test.NASDecode(ue, nas.GetSecurityHeaderType(payload), payload)
			assert.Nil(t, err)
			guti = m.RegistrationAccept.GUTI5G
		}
	}

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	conn.Close()

	// -----Second registration----- ue re-registration with GUTI

	GUTI5GS := nasType.MobileIdentity5GS{
		Iei:    guti.Iei,
		Len:    guti.Len,
		Buffer: guti.Octet[:],
	}

	// Send registration request to new amf
	innerRegistrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, innerRegistrationRequest, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	registrationRequest = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), pdu, nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	require.Nil(t, err)

	_, err = conn2.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn2.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	require.Nil(t, err)

	// ue send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connections
	conn2.Close()

	NfTerminate()
}

func TestNasReroute(t *testing.T) {
	time.Sleep(3 * time.Second)

	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to old amf
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// RAN connect to new amf
	conn2, err := test.ConnectToAmf(amfN2Ipv4Addr2, ranN2Ipv4Addr, 38413, 9488)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	servingPlmnId := "20893"
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")
	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	var guti *nasType.GUTI5G
	for _, ie := range ngapPdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDNASPDU {
			payload := []byte(ie.Value.NASPDU.Value)
			m, err := test.NASDecode(ue, nas.GetSecurityHeaderType(payload), payload)
			assert.Nil(t, err)
			guti = m.RegistrationAccept.GUTI5G
		}
	}

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	conn.Close()

	// // -----Second registration----- ue re-registration with GUTI

	GUTI5GS := nasType.MobileIdentity5GS{
		Iei:    guti.Iei,
		Len:    guti.Len,
		Buffer: guti.Octet[:],
	}

	// Send registration request to new amf
	a := nasType.NewRequestedNSSAI(nasMessage.RegistrationRequestRequestedNSSAIType)
	a.SetIei(nasMessage.RegistrationRequestRequestedNSSAIType)
	a.SetLen(5)
	a.SetSNSSAIValue([]byte{0x04, 0x01, 0x01, 0x02, 0x03})
	innerRegistrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, a, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, innerRegistrationRequest, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	registrationRequest = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, a, ueSecurityCapability, ue.Get5GMMCapability(), pdu, nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	require.Nil(t, err)

	_, err = conn2.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn2.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeRerouteNASRequest,
		"No RerouteNASRequest received.")

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// close Connections
	conn2.Close()

	NfTerminate()
}

func TestNon3GPPUE(t *testing.T) {
	// New UE
	ue := NewRanUeContext("imsi-2089300007487", 1, nasSecurity.AlgCiphering128NEA0, nasSecurity.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = getAuthSubscription()
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	// Used to save IPsec/IKE related data
	n3ue := new(N3IWFUe)
	n3ue.N3IWFIkeUe.N3iwfCtx = new(n3iwfContext.N3IWFContext)
	n3ue.PduSessionList = make(map[int64]*context.PDUSession)
	n3ue.N3IWFChildSecurityAssociation = make(map[uint32]*context.ChildSecurityAssociation)
	n3ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*context.ChildSecurityAssociation)

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfInfo_IPSecIfaceAddr+":500")
	if err != nil {
		t.Fatalf("Resolve UDP address %s fail: %+v", n3iwfInfo_IPSecIfaceAddr+":500", err)
	}
	udpConnection, err := setupUDPSocket()

	if err != nil {
		t.Fatalf("Setup UDP socket Fail: %+v", err)
	}

	// IKE_SA_INIT
	ikeInitiatorSPI := uint64(123123)
	ikeMessage := new(message.IKEMessage)
	ikeMessage.BuildIKEHeader(ikeInitiatorSPI, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	// Security Association
	securityAssociation := ikeMessage.Payloads.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeIKE, nil)
	// ENCR
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// PRF
	proposal.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	// DH
	proposal.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)

	// Key exchange data
	generator := new(big.Int).SetUint64(security.Group14Generator)
	factor, ok := new(big.Int).SetString(security.Group14PrimeString, 16)
	if !ok {
		t.Fatalf("Generate key exchange data failed")
	}
	secert := security.GenerateRandomNumber()
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	localNonce := security.GenerateRandomNumber().Bytes()
	ikeMessage.Payloads.BuildNonce(localNonce)

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE maessage fail: %+v", err)
	}
	realMessage1, _ := ikeMessage.Encode()
	ikeSecurityAssociation := &context.IKESecurityAssociation{
		ResponderSignedOctets: realMessage1,
	}

	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}

	var sharedKeyExchangeData []byte
	var remoteNonce []byte

	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case message.TypeSA:
			t.Log("Get SA payload")
		case message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secert, factor).Bytes()
		case message.TypeNiNr:
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		}
	}

	ikeSecurityAssociation = &context.IKESecurityAssociation{
		LocalSPI:               ikeInitiatorSPI,
		RemoteSPI:              ikeMessage.ResponderSPI,
		InitiatorMessageID:     0,
		ResponderMessageID:     0,
		EncryptionAlgorithm:    proposal.EncryptionAlgorithm[0],
		IntegrityAlgorithm:     proposal.IntegrityAlgorithm[0],
		PseudorandomFunction:   proposal.PseudorandomFunction[0],
		DiffieHellmanGroup:     proposal.DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
		ResponderSignedOctets:  append(ikeSecurityAssociation.ResponderSignedOctets, remoteNonce...),
	}

	if err := generateKeyForIKESA(ikeSecurityAssociation); err != nil {
		t.Fatalf("Generate key for IKE SA failed: %+v", err)
	}

	n3ue.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	// IKE_AUTH
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(
		n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	var ikePayload message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_KEY_ID, []byte("UE"))

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()
	// Proposal 1
	inboundSPI := generateSPI(n3ue)
	proposal = securityAssociation.Proposals.BuildProposal(1, message.TypeESP, inboundSPI)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		t.Fatalf("Encrypting IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE message failed: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	n3ue.CreateHalfChildSA(n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID, binary.BigEndian.Uint32(inboundSPI), -1)

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE message failed: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE message failed: %+v", err)
	}

	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatalf("Received payload is not an encrypted payload")
	}

	decryptedIKEPayload, err := decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt IKE message failed: %+v", err)
	}

	var eapIdentifier uint8

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeIDr:
			t.Log("Get IDr")
		case message.TypeAUTH:
			t.Log("Get AUTH")
		case message.TypeCERT:
			t.Log("Get CERT")
		case message.TypeEAP:
			eapIdentifier = ikePayload.(*message.EAP).Identifier
			t.Log("Get EAP")
		}
	}

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// AN Parameters
	anParameters := buildEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eap := ikePayload.BuildEAP(message.EAPCodeResponse, eapIdentifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE message failed: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE message failed: %+v", err)
	}

	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE message failed: %+v", err)
	}

	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatalf("Received payload is not an encrypted payload")
	}

	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt IKE message failed: %+v", err)
	}

	var eapReq *message.EAP
	var eapExpanded *message.EAPExpanded

	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		t.Fatalf("Received packet is not an EAP payload")
	}

	var decodedNAS *nas.Message

	eapExpanded, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		t.Fatalf("The EAP data is not an EAP expended.")
	}

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		t.Fatalf("Decode plain NAS fail: %+v", err)
	}

	// Calculate for RES*
	assert.NotNil(t, decodedNAS)
	rand := decodedNAS.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eap = ikePayload.BuildEAP(message.EAPCodeResponse, eapReq.Identifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	err = encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatal("Received pakcet is not an encrypted payload")
	}
	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt IKE message failed: %+v", err)
		return
	}
	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		t.Fatal("Received packet is not an EAP payload")
		return
	}
	eapExpanded, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		t.Fatal("Received packet is not an EAP expended payload")
		return
	}

	nasData = eapExpanded.VendorData[4:]

	// Send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eap = ikePayload.BuildEAP(message.EAPCodeResponse, eapReq.Identifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	err = encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
		return
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatal("Received pakcet is not an encrypted payload")
	}
	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		t.Fatal("Received packet is not an EAP payload")
	}
	if eapReq.Code != message.EAPCodeSuccess {
		t.Fatal("Not Success")
	}

	// IKE_AUTH - Authentication
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// Authentication
	// Derive Kn3iwf
	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, ue.ULCount.Get()-1)
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{nasSecurity.AccessTypeNon3GPP}
	L1 := ueauth.KDFLen(P1)

	Kn3iwf, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		t.Fatalf("Get Kn3iwf error : %+v", err)
	}

	pseudorandomFunction, ok := security.NewPseudorandomFunction(ikeSecurityAssociation.SK_pi,
		ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		t.Fatalf("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	var idPayload message.IKEPayloadContainer
	idPayload.BuildIdentificationInitiator(message.ID_KEY_ID, []byte("UE"))
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		t.Fatalf("Encode IKE payload failed : %+v", err)
	}
	if _, err := pseudorandomFunction.Write(idPayloadData[4:]); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	ikeSecurityAssociation.ResponderSignedOctets = append(ikeSecurityAssociation.ResponderSignedOctets,
		pseudorandomFunction.Sum(nil)...)

	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	pseudorandomFunction, ok = security.NewPseudorandomFunction(Kn3iwf, transformPseudorandomFunction.TransformID)
	if !ok {
		t.Fatalf("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	secret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction, ok = security.NewPseudorandomFunction(secret, transformPseudorandomFunction.TransformID)
	if !ok {
		t.Fatalf("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	pseudorandomFunction.Reset()
	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	ikePayload.BuildAuthentication(message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_ADDRESS, nil)

	err = encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatal("Received pakcet is not an encrypted payload")
	}
	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatal(err)

	}

	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *message.SecurityAssociation
	var responseTrafficSelectorInitiator *message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *message.TrafficSelectorResponder
	var responseConfiguration *message.Configuration
	n3iwfNASAddr := new(net.TCPAddr)

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeAUTH:
			t.Log("Get Authentication from N3IWF")
		case message.TypeSA:
			responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		case message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeN:
			notification := ikePayload.(*message.Notification)
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				n3iwfNASAddr.IP = net.IPv4(notification.NotificationData[0], notification.NotificationData[1], notification.NotificationData[2], notification.NotificationData[3])
			}
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				n3iwfNASAddr.Port = int(binary.BigEndian.Uint16(notification.NotificationData))
			}
		case message.TypeCP:
			responseConfiguration = ikePayload.(*message.Configuration)
			if responseConfiguration.ConfigurationType == message.CFG_REPLY {
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == message.INTERNAL_IP4_ADDRESS {
						ueInnerAddr.IP = configAttr.Value
					}
					if configAttr.Type == message.INTERNAL_IP4_NETMASK {
						ueInnerAddr.Mask = configAttr.Value
					}
				}
			}
		}
	}

	OutboundSPI := binary.BigEndian.Uint32(n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
	childSecurityAssociationContext, err := n3ue.CompleteChildSA(
		0x01, OutboundSPI, n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA)
	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext,
		responseTrafficSelectorInitiator.TrafficSelectors[0],
		responseTrafficSelectorResponder.TrafficSelectors[0])

	if err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select TCP traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

	if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	var linkIPSec netlink.Link

	// Setup interface for ipsec
	newXfrmiName := fmt.Sprintf("%s-default", n3ueInfo_XfrmiName)
	if linkIPSec, err = setupIPsecXfrmi(newXfrmiName, n3ueInfo_IPSecIfaceName, n3ueInfo_XfrmiId, ueInnerAddr); err != nil {
		t.Fatalf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
	}

	defer func() {
		if err := netlink.LinkDel(linkIPSec); err != nil {
			t.Fatalf("Delete XFRM interface %s fail: %+v", newXfrmiName, err)
		} else {
			t.Logf("Delete XFRM interface: %s", newXfrmiName)
		}
	}()

	// Aplly XFRM rules
	if err = applyXFRMRule(true, n3ueInfo_XfrmiId, childSecurityAssociationContext); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}

	defer func() {
		_ = netlink.XfrmPolicyFlush()
		_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	}()

	localTCPAddr := &net.TCPAddr{
		IP: ueInnerAddr.IP,
	}
	tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3iwfNASAddr)
	if err != nil {
		t.Fatal(err)
	}

	nasEnv := make([]byte, 65535)

	n, err = tcpConnWithN3IWF.Read(nasEnv)
	if err != nil {
		t.Fatal(err)
		return
	}

	nasEnv, n, err = DecapNasPduFromEnvelope(nasEnv[:n])
	if err != nil {
		t.Fatal(err)
	}
	nasMsg, err := NASDecode(ue, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nasEnv[:n])
	if err != nil {
		t.Fatalf("NAS Decode Fail: %+v", err)
	}

	spew.Config.Indent = "\t"
	nasStr := spew.Sdump(nasMsg)
	t.Logf("Get NAS Security Mode Command Message:\n %+v", nasStr)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
		return
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		t.Fatal(err)
		return
	}

	time.Sleep(500 * time.Millisecond)

	// UE request PDU session setup
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}

	var pduSessionId uint8 = 1

	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
		return
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		t.Fatal(err)
		return
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}
	t.Logf("IKE message exchange type: %d", ikeMessage.ExchangeType)
	t.Logf("IKE message ID: %d", ikeMessage.MessageID)
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		t.Fatal("Received pakcet is not an encrypted payload")
		return
	}
	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatal(err)
		return
	}

	var QoSInfo *PDUQoSInfo

	var upIPAddr net.IP
	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeSA:
			responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			OutboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeN:
			notification := ikePayload.(*message.Notification)
			if notification.NotifyMessageType == message.Vendor3GPPNotifyType5G_QOS_INFO {
				t.Log("Received Qos Flow settings")
				if info, err := parse5GQoSInfoNotify(notification); err == nil {
					QoSInfo = info
					t.Logf("NotificationData:%+v", notification.NotificationData)
					if QoSInfo.isDSCPSpecified {
						t.Logf("DSCP is specified but test not support")
					}
				} else {
					t.Logf("%+v", err)
				}
			}
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				upIPAddr = notification.NotificationData[:4]
				t.Logf("UP IP Address: %+v\n", upIPAddr)
			}
		case message.TypeNiNr:
			responseNonce := ikePayload.(*message.Nonce)
			ikeSecurityAssociation.ConcatenatedNonce = responseNonce.NonceData
		}
	}

	// IKE CREATE_CHILD_SA response
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.ResponderMessageID = ikeMessage.MessageID
	ikeMessage.BuildIKEHeader(ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI, message.CREATE_CHILD_SA,
		message.ResponseBitCheck|message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.ResponderMessageID)

	ikePayload.Reset()

	// SA
	inboundSPI = generateSPI(n3ue)
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonce = security.GenerateRandomNumber().Bytes()
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	n3ue.CreateHalfChildSA(n3ue.N3IWFIKESecurityAssociation.ResponderMessageID, binary.BigEndian.Uint32(inboundSPI), -1)
	childSecurityAssociationContextUserPlane, err := n3ue.CompleteChildSA(
		n3ue.N3IWFIKESecurityAssociation.ResponderMessageID, OutboundSPI, responseSecurityAssociation)

	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContextUserPlane, responseTrafficSelectorResponder.TrafficSelectors[0], responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContextUserPlane); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	// Aplly XFRM rules
	if err = applyXFRMRule(false, n3ueInfo_XfrmiId, childSecurityAssociationContextUserPlane); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}

	// TODO
	// We don't check any of message in UeConfigUpdate Message
	if n, err := tcpConnWithN3IWF.Read(buffer); err != nil {
		t.Fatalf("No UeConfigUpdate Message: %+v", err)
		_, err := ngap.Decoder(buffer[2:n])
		if err != nil {
			t.Fatalf("UeConfigUpdate Decode Error: %+v", err)
		}
	}

	var pduAddress net.IP

	// Read NAS from N3IWF
	if n, err := tcpConnWithN3IWF.Read(buffer); err != nil {
		t.Fatalf("Read NAS Message Fail:%+v", err)
	} else {
		nasMsg, err := DecodePDUSessionEstablishmentAccept(ue, n, buffer)
		if err != nil {
			t.Fatalf("DecodePDUSessionEstablishmentAccept Fail: %+v", err)
		}

		spew.Config.Indent = "\t"
		nasStr := spew.Sdump(nasMsg)
		t.Log("Dump DecodePDUSessionEstablishmentAccept:\n", nasStr)
		pduAddress, err = GetPDUAddress(nasMsg.GsmMessage.PDUSessionEstablishmentAccept)
		if err != nil {
			t.Fatalf("GetPDUAddress Fail: %+v", err)
		}

		t.Logf("PDU Address: %s", pduAddress.String())
	}

	var linkGRE netlink.Link

	newGREName := fmt.Sprintf("%s-id-%d", n3ueInfo_GreIfaceName, n3ueInfo_XfrmiId)

	if linkGRE, err = setupGreTunnel(newGREName, newXfrmiName, ueInnerAddr.IP, upIPAddr, pduAddress, QoSInfo, t); err != nil {
		t.Fatalf("Setup GRE tunnel %s Fail %+v", newGREName, err)
	}

	defer func() {
		_ = netlink.LinkDel(linkGRE)
		t.Logf("Delete interface: %s", linkGRE.Attrs().Name)
	}()

	// Add route
	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	}
	if err := netlink.RouteAdd(upRoute); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		var (
			ifaces []netlink.Link
			err    error
		)
		t.Logf("%d times PDU Session Est Request Start", i+1)
		if ifaces, err = sendPduSessionEstablishmentRequest(pduSessionId+uint8(i), ue, n3ue, ikeSecurityAssociation, udpConnection, tcpConnWithN3IWF, t); err != nil {
			t.Fatalf("Session Est Request Fail: %+v", err)
		} else {
			t.Logf("Create %d interfaces", len(ifaces))
		}

		defer func() {
			for _, iface := range ifaces {
				if err := netlink.LinkDel(iface); err != nil {
					t.Fatalf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
				} else {
					t.Logf("Delete interface: %s", iface.Attrs().Name)
				}
			}
		}()
	}

	// Ping remote
	pinger, err := ping.NewPinger("10.60.0.101")
	if err != nil {
		t.Fatal(err)
		return
	}

	// Run with root
	pinger.SetPrivileged(true)

	pinger.OnRecv = func(pkt *ping.Packet) {
		t.Logf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		t.Logf("\n--- %s ping statistics ---\n", stats.Addr)
		t.Logf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		t.Logf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	pinger.Source = "10.60.0.1"

	time.Sleep(3 * time.Second)

	pinger.Run()

	time.Sleep(1 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		t.Fatal("Ping Failed")
		return
	}
}