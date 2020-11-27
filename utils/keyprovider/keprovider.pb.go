// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto.proto

package keyproviderpb

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type KeyProviderKeyWrapProtocolInput struct {
	KeyProviderKeyWrapProtocolInput []byte   `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolInput,proto3" json:"KeyProviderKeyWrapProtocolInput,omitempty"`
	XXX_NoUnkeyedLiteral            struct{} `json:"-"`
	XXX_unrecognized                []byte   `json:"-"`
	XXX_sizecache                   int32    `json:"-"`
}

func (m *KeyProviderKeyWrapProtocolInput) Reset()         { *m = KeyProviderKeyWrapProtocolInput{} }
func (m *KeyProviderKeyWrapProtocolInput) String() string { return proto.CompactTextString(m) }
func (*KeyProviderKeyWrapProtocolInput) ProtoMessage()    {}
func (*KeyProviderKeyWrapProtocolInput) Descriptor() ([]byte, []int) {
	return fileDescriptor_2fcc84b9998d60d8, []int{0}
}

func (m *KeyProviderKeyWrapProtocolInput) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Unmarshal(m, b)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Marshal(b, m, deterministic)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Merge(m, src)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Size() int {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Size(m)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyProviderKeyWrapProtocolInput.DiscardUnknown(m)
}

var xxx_messageInfo_KeyProviderKeyWrapProtocolInput proto.InternalMessageInfo

func (m *KeyProviderKeyWrapProtocolInput) GetKeyProviderKeyWrapProtocolInput() []byte {
	if m != nil {
		return m.KeyProviderKeyWrapProtocolInput
	}
	return nil
}

type KeyProviderKeyWrapProtocolOutput struct {
	KeyProviderKeyWrapProtocolOutput []byte   `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolOutput,proto3" json:"KeyProviderKeyWrapProtocolOutput,omitempty"`
	XXX_NoUnkeyedLiteral             struct{} `json:"-"`
	XXX_unrecognized                 []byte   `json:"-"`
	XXX_sizecache                    int32    `json:"-"`
}

func (m *KeyProviderKeyWrapProtocolOutput) Reset()         { *m = KeyProviderKeyWrapProtocolOutput{} }
func (m *KeyProviderKeyWrapProtocolOutput) String() string { return proto.CompactTextString(m) }
func (*KeyProviderKeyWrapProtocolOutput) ProtoMessage()    {}
func (*KeyProviderKeyWrapProtocolOutput) Descriptor() ([]byte, []int) {
	return fileDescriptor_2fcc84b9998d60d8, []int{1}
}

func (m *KeyProviderKeyWrapProtocolOutput) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Unmarshal(m, b)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Marshal(b, m, deterministic)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Merge(m, src)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Size() int {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Size(m)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.DiscardUnknown(m)
}

var xxx_messageInfo_KeyProviderKeyWrapProtocolOutput proto.InternalMessageInfo

func (m *KeyProviderKeyWrapProtocolOutput) GetKeyProviderKeyWrapProtocolOutput() []byte {
	if m != nil {
		return m.KeyProviderKeyWrapProtocolOutput
	}
	return nil
}

func init() {
	proto.RegisterType((*KeyProviderKeyWrapProtocolInput)(nil), "hello.keyProviderKeyWrapProtocolInput")
	proto.RegisterType((*KeyProviderKeyWrapProtocolOutput)(nil), "hello.keyProviderKeyWrapProtocolOutput")
}

func init() {
	proto.RegisterFile("proto.proto", fileDescriptor_2fcc84b9998d60d8)
}

var fileDescriptor_2fcc84b9998d60d8 = []byte{
	// 174 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x2e, 0x28, 0xca, 0x2f,
	0xc9, 0xd7, 0x03, 0x93, 0x42, 0xac, 0x19, 0xa9, 0x39, 0x39, 0xf9, 0x4a, 0xd9, 0x5c, 0xf2, 0xd9,
	0xa9, 0x95, 0x01, 0x45, 0xf9, 0x65, 0x99, 0x29, 0xa9, 0x45, 0xde, 0xa9, 0x95, 0xe1, 0x45, 0x89,
	0x05, 0x01, 0x20, 0x15, 0xc9, 0xf9, 0x39, 0x9e, 0x79, 0x05, 0xa5, 0x25, 0x42, 0x1e, 0x5c, 0xf2,
	0xde, 0xf8, 0x95, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0xf0, 0x04, 0x11, 0x52, 0xa6, 0x94, 0xc7, 0xa5,
	0x80, 0xdb, 0x32, 0xff, 0xd2, 0x12, 0x90, 0x6d, 0x5e, 0x5c, 0x0a, 0xde, 0x04, 0xd4, 0x40, 0xad,
	0x23, 0xa8, 0xce, 0xe8, 0x12, 0x23, 0x97, 0x10, 0x92, 0xa2, 0xe0, 0xd4, 0xa2, 0xb2, 0xcc, 0xe4,
	0x54, 0xa1, 0x18, 0x2e, 0x76, 0x90, 0x62, 0xa0, 0x8c, 0x90, 0x9a, 0x1e, 0x38, 0x18, 0xf4, 0x08,
	0x84, 0x81, 0x94, 0x3a, 0x41, 0x75, 0x10, 0x2b, 0x95, 0x18, 0x84, 0xe2, 0xb8, 0x38, 0x43, 0xf3,
	0x68, 0x67, 0xbe, 0x13, 0x67, 0x14, 0x3b, 0x58, 0x6d, 0x41, 0x52, 0x12, 0x1b, 0x38, 0x2a, 0x8d,
	0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xb0, 0x77, 0xef, 0x0a, 0xd9, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// KeyProviderServiceClient is the client API for KeyProviderService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type KeyProviderServiceClient interface {
	WrapKey(ctx context.Context, in *KeyProviderKeyWrapProtocolInput, opts ...grpc.CallOption) (*KeyProviderKeyWrapProtocolOutput, error)
	UnWrapKey(ctx context.Context, in *KeyProviderKeyWrapProtocolInput, opts ...grpc.CallOption) (*KeyProviderKeyWrapProtocolOutput, error)
}

type keyProviderServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyProviderServiceClient(cc grpc.ClientConnInterface) KeyProviderServiceClient {
	return &keyProviderServiceClient{cc}
}

func (c *keyProviderServiceClient) WrapKey(ctx context.Context, in *KeyProviderKeyWrapProtocolInput, opts ...grpc.CallOption) (*KeyProviderKeyWrapProtocolOutput, error) {
	out := new(KeyProviderKeyWrapProtocolOutput)
	err := c.cc.Invoke(ctx, "/hello.KeyProviderService/WrapKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyProviderServiceClient) UnWrapKey(ctx context.Context, in *KeyProviderKeyWrapProtocolInput, opts ...grpc.CallOption) (*KeyProviderKeyWrapProtocolOutput, error) {
	out := new(KeyProviderKeyWrapProtocolOutput)
	err := c.cc.Invoke(ctx, "/hello.KeyProviderService/UnWrapKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyProviderServiceServer is the server API for KeyProviderService service.
type KeyProviderServiceServer interface {
	WrapKey(context.Context, *KeyProviderKeyWrapProtocolInput) (*KeyProviderKeyWrapProtocolOutput, error)
	UnWrapKey(context.Context, *KeyProviderKeyWrapProtocolInput) (*KeyProviderKeyWrapProtocolOutput, error)
}

// UnimplementedKeyProviderServiceServer can be embedded to have forward compatible implementations.
type UnimplementedKeyProviderServiceServer struct {
}

func (*UnimplementedKeyProviderServiceServer) WrapKey(ctx context.Context, req *KeyProviderKeyWrapProtocolInput) (*KeyProviderKeyWrapProtocolOutput, error) {
	return nil, status.Errorf(codes.Unimplemented, "method WrapKey not implemented")
}
func (*UnimplementedKeyProviderServiceServer) UnWrapKey(ctx context.Context, req *KeyProviderKeyWrapProtocolInput) (*KeyProviderKeyWrapProtocolOutput, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnWrapKey not implemented")
}

func RegisterKeyProviderServiceServer(s *grpc.Server, srv KeyProviderServiceServer) {
	s.RegisterService(&_KeyProviderService_serviceDesc, srv)
}

func _KeyProviderService_WrapKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyProviderKeyWrapProtocolInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyProviderServiceServer).WrapKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hello.KeyProviderService/WrapKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyProviderServiceServer).WrapKey(ctx, req.(*KeyProviderKeyWrapProtocolInput))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyProviderService_UnWrapKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyProviderKeyWrapProtocolInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyProviderServiceServer).UnWrapKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hello.KeyProviderService/UnWrapKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyProviderServiceServer).UnWrapKey(ctx, req.(*KeyProviderKeyWrapProtocolInput))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyProviderService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hello.KeyProviderService",
	HandlerType: (*KeyProviderServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "WrapKey",
			Handler:    _KeyProviderService_WrapKey_Handler,
		},
		{
			MethodName: "UnWrapKey",
			Handler:    _KeyProviderService_UnWrapKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto.proto",
}
