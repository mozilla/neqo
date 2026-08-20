#! /usr/bin/env bash

# This script builds the client and server binaries and runs them in a tmux
# session side-by-side. The client connects to the server and the server
# responds with a simple HTTP response. The client and server are run with
# verbose logging and the qlog output is stored in a temporary directory. The
# script also runs tcpdump to capture the packets exchanged between the client
# and server. The script uses tmux to create a split terminal window to display
# the qlog output and the packet capture.

set -e

missing=
for tool in cargo tmux tcpdump tshark; do
        command -v "$tool" >/dev/null || missing+=" $tool"
done
[ -z "$missing" ] || { echo "missing tools:$missing" >&2; exit 1; }

tmp=$(mktemp -d)

cargo build --locked --bin neqo-client --bin neqo-server

addr=localhost
port=4433
path=/20000
flags="--verbose --verbose --verbose --qlog-dir $tmp --alpn hq-interop --quic-version 1"
if [ "$(uname -s)" != "Linux" ]; then
        iface=lo0
else
        iface=lo
fi

if [ "$NSS_DIR" ] && [ "$NSS_TARGET" ]; then
        export LD_LIBRARY_PATH="$NSS_DIR/../dist/$NSS_TARGET/lib"
        export DYLD_FALLBACK_LIBRARY_PATH="$LD_LIBRARY_PATH"
fi

# There is no way to add a column, only to replace the whole set, so restate the ports, which tell
# client and server apart on loopback, and pin the time to seconds since the first packet.
columns='"No.","%m","Time","%Rt","Source","%s","SPort","%uS","Destination","%d","DPort","%uD"'
columns+=',"Protocol","%p","Length","%L","Info","%i"'

# Append to the info column what each QUIC frame covers. A column cannot do this, because it appends
# all occurrences of a field before moving to the next one, which groups the values per field instead
# of per frame. Walking the dissection tree keeps them together.
cat >"$tmp/quic-trace.lua" <<'EOF'
local labels = { ["quic.crypto.offset"] = "", ["quic.crypto.length"] = "", ["quic.stream.fin"] = "",
    ["quic.stream.stream_id"] = "id", ["quic.stream.offset"] = "off", ["quic.stream_data"] = "len",
    ["quic.ack.largest_acknowledged"] = "", ["quic.ack.first_ack_range"] = "",
    ["quic.ack.gap"] = "gap", ["quic.ack.ack_range"] = "range" }
local listener = Listener.new(nil, nil, true) -- All fields, so that the dissection tree exists.
function listener.packet(pinfo, _, _)
    local detail, frame = {}, nil
    for _, field in ipairs({ all_field_infos() }) do
        if field.name == "quic.frame_type" then
            frame = { (tostring(field.display):gsub("%s*%(0x%x+%)$", "")) }
        elseif frame and labels[field.name] and field.value ~= false then
            if #frame == 1 then detail[#detail + 1] = frame end
            frame[#frame + 1] = field.name == "quic.stream.fin" and "FIN" or labels[field.name] ..
                (field.name == "quic.stream_data" and field.len or tostring(field.value))
        end
    end
    for i, each in ipairs(detail) do -- FIN sits in the frame type, so it comes first but reads last.
        detail[i] = each[1] .. "(" .. (each[2] == "FIN" and table.concat(each, ",", 3) .. ",FIN"
            or table.concat(each, ",", 2)) .. ")"
    end
    if #detail > 0 then pinfo.cols.info:append(" — " .. table.concat(detail, ", ")) end
end
EOF

# SNI slicing sends the ClientHello's CRYPTO frames out of order, and tshark does not reassemble a
# handshake message that does not start at offset 0. Without the ClientHello it never learns the
# client random, so it cannot apply the keylog and only the Initial packets end up decrypted.
client="./target/debug/neqo-client $flags --no-sni-slicing --output-dir $tmp --stats=$tmp/client-stats.json https://$addr:$port$path"
server="SSLKEYLOGFILE=$tmp/test.tlskey ./target/debug/neqo-server $flags --stats=$tmp/server-stats.json $addr:$port"

tcpdump -U -i "$iface" -w "$tmp/test.pcap" host $addr and port $port \
        >/dev/null 2>"$tmp/tcpdump.log" &
tcpdump_pid=$!
trap 'kill $tcpdump_pid; rm -rf "$tmp"' EXIT

tmux \
        set-option -g default-shell "$(command -v bash)" \; \
        new-session "$client; kill -USR2 $tcpdump_pid; touch $tmp/done" \; \
        split-window -h "$server" \; \
        split-window -v -f "\
                until [ -e $tmp/done ]; do sleep 1; done; \
                echo $tmp; ls -l $tmp; echo; \
                tail -n +1 $tmp/*-stats.json; echo; \
                tshark -r $tmp/test.pcap -o tls.keylog_file:$tmp/test.tlskey \
                        -o gui.column.format:'$columns' -X lua_script:$tmp/quic-trace.lua" \; \
        set remain-on-exit on
