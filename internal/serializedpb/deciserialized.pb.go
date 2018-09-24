// Code generated by protoc-gen-go. DO NOT EDIT.
// source: deciserialized.proto

package serializedpb

/*
Package internal holds protobuf types used by the server
*/

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// RefreshToken is a message that holds refresh token data used by dex.
type RefreshToken struct {
	RefreshId            string   `protobuf:"bytes,1,opt,name=refresh_id,json=refreshId,proto3" json:"refresh_id,omitempty"`
	Token                string   `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RefreshToken) Reset()         { *m = RefreshToken{} }
func (m *RefreshToken) String() string { return proto.CompactTextString(m) }
func (*RefreshToken) ProtoMessage()    {}
func (*RefreshToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_deciserialized_fdc3d6c71c35142c, []int{0}
}
func (m *RefreshToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RefreshToken.Unmarshal(m, b)
}
func (m *RefreshToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RefreshToken.Marshal(b, m, deterministic)
}
func (dst *RefreshToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RefreshToken.Merge(dst, src)
}
func (m *RefreshToken) XXX_Size() int {
	return xxx_messageInfo_RefreshToken.Size(m)
}
func (m *RefreshToken) XXX_DiscardUnknown() {
	xxx_messageInfo_RefreshToken.DiscardUnknown(m)
}

var xxx_messageInfo_RefreshToken proto.InternalMessageInfo

func (m *RefreshToken) GetRefreshId() string {
	if m != nil {
		return m.RefreshId
	}
	return ""
}

func (m *RefreshToken) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func init() {
	proto.RegisterType((*RefreshToken)(nil), "deciserialized.RefreshToken")
}

func init() {
	proto.RegisterFile("deciserialized.proto", fileDescriptor_deciserialized_fdc3d6c71c35142c)
}

var fileDescriptor_deciserialized_fdc3d6c71c35142c = []byte{
	// 114 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0x12, 0x49, 0x49, 0x4d, 0xce,
	0x2c, 0x4e, 0x2d, 0xca, 0x4c, 0xcc, 0xc9, 0xac, 0x4a, 0x4d, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9,
	0x17, 0xe2, 0x43, 0x15, 0x55, 0x72, 0xe6, 0xe2, 0x09, 0x4a, 0x4d, 0x2b, 0x4a, 0x2d, 0xce, 0x08,
	0xc9, 0xcf, 0x4e, 0xcd, 0x13, 0x92, 0xe5, 0xe2, 0x2a, 0x82, 0xf0, 0xe3, 0x33, 0x53, 0x24, 0x18,
	0x15, 0x18, 0x35, 0x38, 0x83, 0x38, 0xa1, 0x22, 0x9e, 0x29, 0x42, 0x22, 0x5c, 0xac, 0x25, 0x20,
	0x75, 0x12, 0x4c, 0x60, 0x19, 0x08, 0xc7, 0x89, 0x2f, 0x8a, 0x07, 0x61, 0x64, 0x41, 0x52, 0x12,
	0x1b, 0xd8, 0x2e, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0x52, 0xac, 0xa5, 0xae, 0x83, 0x00,
	0x00, 0x00,
}