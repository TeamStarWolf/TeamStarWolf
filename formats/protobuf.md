# Protocol Buffers

Protocol Buffers, often shortened to protobuf, is a binary serialization format from Google. You define message structures in a `.proto` schema, then a compiler generates code to read and write a compact binary wire format. It is widely used for service APIs, especially with gRPC, and for stored records where size and speed matter. Unlike text formats, protobuf data is not self-describing, so the reader needs the schema.

## What it is and where it is used

Protobuf serializes structured data into a small binary form. A schema file names each message and its fields, and each field carries a number used on the wire. The compiler, `protoc`, turns the schema into classes or structs in many languages.

It is common in:

- gRPC service definitions, where messages are request and response types.
- Internal service-to-service communication at scale.
- Stored records and logs where compactness reduces cost.
- Mobile and embedded contexts that benefit from small payloads.

The binary form is not human-readable and cannot be decoded correctly without the matching schema.

## Syntax and structure

A schema starts with a syntax declaration and defines messages. Each field has a type, a name, and a field number.

```protobuf
syntax = "proto3";

message User {
  int32 id = 1;
  string name = 2;
  bool active = 3;
}
```

Field numbers identify fields on the wire. They must be unique within a message and must not change once in use, because the number, not the name, is what gets serialized.

Scalar types include `int32`, `int64`, `uint32`, `float`, `double`, `bool`, `string`, and `bytes`. The `repeated` keyword marks a field that holds a list of values.

```protobuf
message Order {
  string id = 1;
  repeated string item = 2;
  double total = 3;
}
```

A `oneof` lets at most one of a set of fields be set at a time. An `enum` defines a named set of integer constants, and proto3 requires the first enum value to be zero.

```protobuf
message Event {
  enum Kind {
    KIND_UNKNOWN = 0;
    KIND_LOGIN = 1;
    KIND_LOGOUT = 2;
  }
  Kind kind = 1;

  oneof payload {
    string text = 2;
    bytes blob = 3;
  }
}
```

The wire format encodes each field as its number plus a type tag, then the value. Because fields are keyed by number, schema evolution follows rules: you may add fields with new numbers, and old readers ignore fields they do not know. You must not reuse or renumber an existing field. Reserve retired field numbers and names to prevent accidental reuse.

```protobuf
message Account {
  reserved 4, 5;
  reserved "legacy_token";
  string id = 1;
  string email = 2;
}
```

## A worked example

```protobuf
syntax = "proto3";

package billing.v1;

// A single invoice line.
message LineItem {
  string sku = 1;
  uint32 quantity = 2;
  double unit_price = 3;
}

message Invoice {
  string invoice_id = 1;
  string customer_id = 2;
  repeated LineItem items = 3;
  double total = 4;

  enum Status {
    STATUS_UNSPECIFIED = 0;
    STATUS_DRAFT = 1;
    STATUS_SENT = 2;
    STATUS_PAID = 3;
  }
  Status status = 5;

  reserved 6;  // retired "notes" field
}

service InvoiceService {
  rpc GetInvoice(GetInvoiceRequest) returns (Invoice);
}

message GetInvoiceRequest {
  string invoice_id = 1;
}
```

## Tooling

- `protoc` is the reference compiler and generates code for C++, Java, Python, Go, C#, and more.
- `buf` provides linting, breaking-change detection, and schema management.
- gRPC uses protobuf as its interface definition language.
- Language libraries (for example `protobuf` for Python, `google.golang.org/protobuf` for Go) carry the runtime.
- `protoc --decode` and `protoscope` help inspect binary payloads during debugging.

Keep schemas under version control and run breaking-change checks in continuous integration before publishing a new version.

## Security considerations

Protobuf avoids some text-format pitfalls, but binary parsing of untrusted input has its own risks.

- Resource exhaustion from untrusted input (CWE-400, Uncontrolled Resource Consumption). A malicious payload can declare huge lengths or deeply nested messages to exhaust memory or stack. Set maximum message size limits and recursion depth limits in the parser before accepting external data. Reject oversized frames early.
- Not self-describing (CWE-20, Improper Input Validation). The bytes mean nothing without the schema. A reader using the wrong schema version can misinterpret fields silently. Version your schemas, follow the field-number rules, and reserve retired numbers and names so they are never reused.
- Unknown-field handling. By design, parsers may keep fields they do not recognize and pass them through on re-serialization. This can carry unexpected or attacker-supplied data across a system that only validates known fields. Decide explicitly whether to preserve or drop unknown fields, and validate every field your logic depends on.
- No deserialization-to-code risk. Protobuf does not construct arbitrary objects or execute code on decode, so it avoids the class of flaw seen in some YAML and native-serialization libraries. The data still needs validation; a well-formed message is not a trusted message.
- Field presence. In proto3, scalar fields have default values rather than being absent, which can mask the difference between zero and unset. Use explicit presence or wrapper types when that distinction is security-relevant.

See `/SECURE_CODING_REFERENCE.md` for input-validation and resource-limit guidance.

## Resources

- The Protocol Buffers documentation and language guide by Google.

## Related pages

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/json.md
- /formats/xml.md
- /formats/yaml.md
