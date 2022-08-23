// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.6.1
// source: api/api.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Risk describes a risk found in a source file
type Risk struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// category is a risk category like SECRET, NIL, or PII
	Category string `protobuf:"bytes,1,opt,name=category,proto3" json:"category,omitempty"`
	// type is a risk type, e.g. password_assignment
	Type string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	// repo_file_path is file path relative to the repo's root directory
	// where the risk was found
	// can be empty if the file is not in the repo directory
	RepoFilePath string `protobuf:"bytes,3,opt,name=repo_file_path,json=repoFilePath,proto3" json:"repo_file_path,omitempty"`
	// line1 is the start line number where the risk was found
	// line number is one-based
	Line1 int32 `protobuf:"varint,4,opt,name=line1,proto3" json:"line1,omitempty"`
	// line2 is the end line number where the risk was found
	// note: for most risks line2 will be the same as line1
	Line2 int32 `protobuf:"varint,5,opt,name=line2,proto3" json:"line2,omitempty"`
	// col1 is the start column number where the risk was found
	// column number is one-based
	Col1 int32 `protobuf:"varint,6,opt,name=col1,proto3" json:"col1,omitempty"`
	// col2 is the end column number where the risk was found
	Col2 int32 `protobuf:"varint,7,opt,name=col2,proto3" json:"col2,omitempty"`
	// tags are an arbitrary meta information assigned to the risk
	// the map's keys are tag names;
	// the values are json-encoded per-tag specific data
	Tags map[string]string `protobuf:"bytes,8,rep,name=tags,proto3" json:"tags,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// severity is risk severity like info, low, medium, high, critical
	Severity string `protobuf:"bytes,9,opt,name=severity,proto3" json:"severity,omitempty"`
	// value is the risk value
	Value string `protobuf:"bytes,10,opt,name=value,proto3" json:"value,omitempty"`
	// textual_context is text around the risk value
	TextualContext string `protobuf:"bytes,11,opt,name=textual_context,json=textualContext,proto3" json:"textual_context,omitempty"`
}

func (x *Risk) Reset() {
	*x = Risk{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Risk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Risk) ProtoMessage() {}

func (x *Risk) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Risk.ProtoReflect.Descriptor instead.
func (*Risk) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{0}
}

func (x *Risk) GetCategory() string {
	if x != nil {
		return x.Category
	}
	return ""
}

func (x *Risk) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Risk) GetRepoFilePath() string {
	if x != nil {
		return x.RepoFilePath
	}
	return ""
}

func (x *Risk) GetLine1() int32 {
	if x != nil {
		return x.Line1
	}
	return 0
}

func (x *Risk) GetLine2() int32 {
	if x != nil {
		return x.Line2
	}
	return 0
}

func (x *Risk) GetCol1() int32 {
	if x != nil {
		return x.Col1
	}
	return 0
}

func (x *Risk) GetCol2() int32 {
	if x != nil {
		return x.Col2
	}
	return 0
}

func (x *Risk) GetTags() map[string]string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *Risk) GetSeverity() string {
	if x != nil {
		return x.Severity
	}
	return ""
}

func (x *Risk) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Risk) GetTextualContext() string {
	if x != nil {
		return x.TextualContext
	}
	return ""
}

// AnalyzeStreamMetadata contains stream metadata attribute(s)
// context may contain contextual information needed for co-relation
type AnalyzeStreamMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StreamName string `protobuf:"bytes,1,opt,name=stream_name,json=streamName,proto3" json:"stream_name,omitempty"`
	Context    string `protobuf:"bytes,2,opt,name=context,proto3" json:"context,omitempty"`
}

func (x *AnalyzeStreamMetadata) Reset() {
	*x = AnalyzeStreamMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyzeStreamMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyzeStreamMetadata) ProtoMessage() {}

func (x *AnalyzeStreamMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyzeStreamMetadata.ProtoReflect.Descriptor instead.
func (*AnalyzeStreamMetadata) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{1}
}

func (x *AnalyzeStreamMetadata) GetStreamName() string {
	if x != nil {
		return x.StreamName
	}
	return ""
}

func (x *AnalyzeStreamMetadata) GetContext() string {
	if x != nil {
		return x.Context
	}
	return ""
}

// AnalyzeStreamRequest contains input parameters for AnalyzeStream method
type AnalyzeStreamRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// metadata contains stream metadata. it is sent only in the first msg on stream.
	Metadata *AnalyzeStreamMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// data contains chunk of data. it is sent in one or more msgs (after metadata msg) on stream.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *AnalyzeStreamRequest) Reset() {
	*x = AnalyzeStreamRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyzeStreamRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyzeStreamRequest) ProtoMessage() {}

func (x *AnalyzeStreamRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyzeStreamRequest.ProtoReflect.Descriptor instead.
func (*AnalyzeStreamRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{2}
}

func (x *AnalyzeStreamRequest) GetMetadata() *AnalyzeStreamMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *AnalyzeStreamRequest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

// AnalyzeStreamResponse contains a response for AnalyzeStream method
type AnalyzeStreamResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// risk contains information about found risk
	Risk *Risk `protobuf:"bytes,1,opt,name=risk,proto3" json:"risk,omitempty"`
	// context is the context sent in metadata msg
	Context string `protobuf:"bytes,2,opt,name=context,proto3" json:"context,omitempty"`
}

func (x *AnalyzeStreamResponse) Reset() {
	*x = AnalyzeStreamResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyzeStreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyzeStreamResponse) ProtoMessage() {}

func (x *AnalyzeStreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyzeStreamResponse.ProtoReflect.Descriptor instead.
func (*AnalyzeStreamResponse) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{3}
}

func (x *AnalyzeStreamResponse) GetRisk() *Risk {
	if x != nil {
		return x.Risk
	}
	return nil
}

func (x *AnalyzeStreamResponse) GetContext() string {
	if x != nil {
		return x.Context
	}
	return ""
}

var File_api_api_proto protoreflect.FileDescriptor

var file_api_api_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x61, 0x70, 0x69, 0x22, 0xed, 0x02, 0x0a, 0x04, 0x52, 0x69, 0x73, 0x6b, 0x12, 0x1a, 0x0a,
	0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x24, 0x0a,
	0x0e, 0x72, 0x65, 0x70, 0x6f, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x70, 0x6f, 0x46, 0x69, 0x6c, 0x65, 0x50,
	0x61, 0x74, 0x68, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x69, 0x6e, 0x65, 0x31, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x6c, 0x69, 0x6e, 0x65, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x69, 0x6e,
	0x65, 0x32, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6c, 0x69, 0x6e, 0x65, 0x32, 0x12,
	0x12, 0x0a, 0x04, 0x63, 0x6f, 0x6c, 0x31, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x63,
	0x6f, 0x6c, 0x31, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x6c, 0x32, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x04, 0x63, 0x6f, 0x6c, 0x32, 0x12, 0x27, 0x0a, 0x04, 0x74, 0x61, 0x67, 0x73, 0x18,
	0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x52, 0x69, 0x73, 0x6b,
	0x2e, 0x54, 0x61, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x04, 0x74, 0x61, 0x67, 0x73,
	0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x74, 0x65, 0x78, 0x74, 0x75, 0x61, 0x6c, 0x5f, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x65, 0x78,
	0x74, 0x75, 0x61, 0x6c, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x1a, 0x37, 0x0a, 0x09, 0x54,
	0x61, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x22, 0x52, 0x0a, 0x15, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x53,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1f, 0x0a,
	0x0b, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x22, 0x62, 0x0a, 0x14, 0x41, 0x6e, 0x61, 0x6c,
	0x79, 0x7a, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x36, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65,
	0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x50, 0x0a, 0x15,
	0x41, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x04, 0x72, 0x69, 0x73, 0x6b, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x52, 0x69, 0x73, 0x6b, 0x52, 0x04,
	0x72, 0x69, 0x73, 0x6b, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x32, 0x58,
	0x0a, 0x0a, 0x42, 0x6c, 0x75, 0x42, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x4a, 0x0a, 0x0d,
	0x41, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x19, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x41,
	0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x30, 0x01, 0x42, 0x36, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x42, 0x6c, 0x75, 0x42, 0x72, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x2d, 0x72, 0x69, 0x73, 0x6b, 0x2d,
	0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x61, 0x70, 0x69,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_api_proto_rawDescOnce sync.Once
	file_api_api_proto_rawDescData = file_api_api_proto_rawDesc
)

func file_api_api_proto_rawDescGZIP() []byte {
	file_api_api_proto_rawDescOnce.Do(func() {
		file_api_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_api_proto_rawDescData)
	})
	return file_api_api_proto_rawDescData
}

var file_api_api_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_api_api_proto_goTypes = []interface{}{
	(*Risk)(nil),                  // 0: api.Risk
	(*AnalyzeStreamMetadata)(nil), // 1: api.AnalyzeStreamMetadata
	(*AnalyzeStreamRequest)(nil),  // 2: api.AnalyzeStreamRequest
	(*AnalyzeStreamResponse)(nil), // 3: api.AnalyzeStreamResponse
	nil,                           // 4: api.Risk.TagsEntry
}
var file_api_api_proto_depIdxs = []int32{
	4, // 0: api.Risk.tags:type_name -> api.Risk.TagsEntry
	1, // 1: api.AnalyzeStreamRequest.metadata:type_name -> api.AnalyzeStreamMetadata
	0, // 2: api.AnalyzeStreamResponse.risk:type_name -> api.Risk
	2, // 3: api.BluBracket.AnalyzeStream:input_type -> api.AnalyzeStreamRequest
	3, // 4: api.BluBracket.AnalyzeStream:output_type -> api.AnalyzeStreamResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_api_api_proto_init() }
func file_api_api_proto_init() {
	if File_api_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Risk); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyzeStreamMetadata); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyzeStreamRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyzeStreamResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_api_proto_goTypes,
		DependencyIndexes: file_api_api_proto_depIdxs,
		MessageInfos:      file_api_api_proto_msgTypes,
	}.Build()
	File_api_api_proto = out.File
	file_api_api_proto_rawDesc = nil
	file_api_api_proto_goTypes = nil
	file_api_api_proto_depIdxs = nil
}
