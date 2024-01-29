#!/bin/bash

set -e

server_address=127.0.0.1
server_port=4433
upload_size=8388608
cc=cubic
client="cargo run --release --bin neqo-client -- http://$server_address:$server_port/ --test upload --upload-size $upload_size --cc $cc"
server="cargo run --release --bin neqo-server -- --db ../test-fixture/db $server_address:$server_port"
server_pid=0
pacing=true
if [ "$pacing" = true ]; then
    client="$client --pacing"
fi

# Define two indexed arrays to store network conditions
network_conditions=("cable" "3g_slow" "DSL" "LTE" "fast wifi")
network_bandwidths=("5Mbit/s" "400Kbit/s" "2Mbit/s" "12Mbit/s" "100Mbit/s")
network_rtts=("14" "200" "25" "35" "10")
plrs=("0.0001" "0.0005" "0.001" "0.002" "0.005")

runs=1

echo -n "Enter root password: "
read -s root_password
echo

setup_network_conditions() {
    bw="$1"
    delay_ms="$2"
    plr="$3"
    delay_s=$(echo "scale=5; $delay_ms / 1000" | bc -l)
    if [[ $bw == *"Mbit/s"* ]]; then
        bw_value=$(echo "$bw" | sed 's/Mbit\/s//') # Remove 'Mbit/s'
        bw_bits_per_second=$(echo "$bw_value * 1000000" | bc) # Convert from Mbits to bits
    elif [[ $bw == *"Kbit/s"* ]]; then
        bw_value=$(echo "$bw" | sed 's/Kbit\/s//') # Remove 'Kbit/s'
        bw_bits_per_second=$(echo "$bw_value * 1000" | bc) # Convert from Kbits to bits
    fi

    bdp_bits=$(echo "$bw_bits_per_second * $delay_s" | bc)

    # Convert BDP to kilobytes
    bdp_kb=$(echo "scale=2; $bdp_bits / 8 / 1024" | bc)
    bdp_kb_rounded_up=$(LC_NUMERIC=C printf "%.0f" "$bdp_kb")


    # if we are on MacOS X, configure the firewall to add delay and queue traffic
    if [ -x /usr/sbin/dnctl ]; then
        set_condition_commands=(
            "sudo dnctl pipe 1 config bw $bw delay $delay_ms plr $plr queue ${bdp_kb_rounded_up}Kbytes noerror"
            "sudo dnctl pipe 2 config bw $bw delay $delay_ms plr $plr queue ${bdp_kb_rounded_up}Kbytes noerror"
            "sudo echo 'dummynet in proto {udp} from any to localhost pipe 1' | sudo pfctl -f -"
            "sudo echo 'dummynet in proto {udp} from localhost to any pipe 2' | sudo pfctl -f -"
            "sudo pfctl -e || true"
        )
    else
        bw_in_bits_per_sec="${bw%/s}"
        bdp_bytes=$(echo "scale=2; $bdp_bits / 8" | bc)
        bdp_bytes_rounded_up=$(LC_NUMERIC=C printf "%.0f" "$bdp_bytes")
        plr_p=$(echo "scale=4; $plr * 100" | bc)
        plr_p=$(LC_NUMERIC=C printf "%.2f" "$plr_p")
        set_condition_commands=(
            "sudo tc qdisc add dev lo root handle 1: tbf rate $bw_in_bits_per_sec burst $bdp_bytes_rounded_up limit 30000"
            "sudo tc qdisc add dev lo parent 1:1 handle 10: netem delay ${delay_ms}ms loss ${plr_p}%"
        )
    fi

    for command in "${set_condition_commands[@]}"; do
        echo $command
        echo $root_password | sudo -S bash -c "$command"
    done
}

stop_network_conditions() {
    if [ -x /usr/sbin/dnctl ]; then
        stop_condition_commands=(
            "sudo pfctl -f /etc/pf.conf"
            "sudo dnctl -q flush"
        )
    else
        stop_condition_commands=(
            "tc qdisc del dev lo root"
        )
    fi

    for command in "${stop_condition_commands[@]}"; do
        echo $root_password | sudo -S bash -c "$command"
    done
}

stop_server() {
    echo "stop server"
    server_pid=$(pgrep -f "neqo-server")
    # Kill the server
    kill $server_pid
}

start_test() {
    echo "start_test"
    eval "$server" > /dev/null 2>&1 & sleep 1

    # Run the client command and capture its output
    echo "Running client..."
    client_output=$(eval "$client")
    echo "Client output: $client_output"
}

cleanup() {
    echo "clean up"
    stop_server
    stop_network_conditions
}

trap cleanup SIGINT

for i in "${!network_conditions[@]}"; do
    condition=${network_conditions[$i]}
    bandwidth=${network_bandwidths[$i]}
    rtt=${network_rtts[$i]}

    for plr in "${plrs[@]}"; do
        echo "Setting up tests for condition: $condition, Bandwidth: $bandwidth, RTT: $rtt, Packet Loss Rate: $plr"

        for r in $(seq 1 $runs); do
            echo "Test Run: $r | Condition: $condition | Bandwidth: $bandwidth | RTT: $rtt | PLR: $plr | Start"
            setup_network_conditions "$bandwidth" "$rtt" "$plr"
            start_test
            cleanup
            echo "Test Run: $r | Condition: $condition | Bandwidth: $bandwidth | RTT: $rtt | PLR: $plr | End"
        done
    done

    echo "Completed tests for condition: $condition."
done

echo "All test runs completed."
