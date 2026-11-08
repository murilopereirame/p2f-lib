// A mock DNS server (UDP) for testing the built-in DNS client.
//   node tools/mock_dns.mjs <port>
// Names:
//   myserver.test   -> A 127.0.0.1
//   alias.test      -> CNAME myserver.test, then A 127.0.0.1 (compressed names)
//   v6only.test     -> no A record (empty answer)
//   anything else   -> NXDOMAIN
import dgram from "node:dgram";

const port = Number(process.argv[2]);
const sock = dgram.createSocket("udp4");

function readName(buf, off) {
  const labels = [];
  while (buf[off] !== 0) { labels.push(buf.subarray(off + 1, off + 1 + buf[off]).toString()); off += 1 + buf[off]; }
  return [labels.join(".").toLowerCase(), off + 1];
}
function encName(name) {
  return Buffer.concat([...name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
}
function rr(nameBytes, type, data) {
  const h = Buffer.alloc(10);
  h.writeUInt16BE(type, 0); h.writeUInt16BE(1, 2); h.writeUInt32BE(60, 4); h.writeUInt16BE(data.length, 8);
  return Buffer.concat([nameBytes, h, data]);
}

sock.on("message", (msg, rinfo) => {
  const [name, qend] = readName(msg, 12);
  const question = msg.subarray(12, qend + 4);
  const hdr = Buffer.from(msg.subarray(0, 12));
  hdr[2] = 0x81; hdr[3] = 0x80; // QR, RD, RA, rcode 0
  hdr.writeUInt16BE(1, 4); hdr.writeUInt16BE(0, 6); hdr.writeUInt16BE(0, 8); hdr.writeUInt16BE(0, 10);
  const ptrQ = Buffer.from([0xc0, 12]); // pointer to the question name
  let answers = [];
  const ip = Buffer.from([127, 0, 0, 1]);
  if (name === "myserver.test") answers = [rr(ptrQ, 1, ip)];
  else if (name === "alias.test") {
    const target = encName("myserver.test");
    const cnameOff = 12 + question.length + 2 + 10; // where the CNAME rdata starts
    answers = [rr(ptrQ, 5, target), rr(Buffer.from([0xc0, cnameOff]), 1, ip)];
  } else if (name === "v6only.test") answers = [];
  else hdr[3] = 0x83; // NXDOMAIN
  hdr.writeUInt16BE(answers.length, 6);
  sock.send(Buffer.concat([hdr, question, ...answers]), rinfo.port, rinfo.address);
});
sock.bind(port, "127.0.0.1", () => console.log(`dns on ${port}`));
