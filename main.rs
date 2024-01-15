use pnet::datalink::Channel::Ethernet;
use serde_derive::{Deserialize, Serialize};
use pnet::datalink::{self};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use dialoguer::{theme::ColorfulTheme, Select, Input};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use pnet::packet::ipv4::Ipv4Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, io, thread};
use std::path::Path;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Rule {
    id: String,
    protocol: String,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    action: String, // "allow" or "block"
}

lazy_static! {
    static ref RULES: Arc<Mutex<Vec<Rule>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    static ref FIREWALL_RUNNING: AtomicBool = AtomicBool::new(false);
}

const RULES_FILE: &str = "firewall_rules.json";

fn save_rules(rules: &Vec<Rule>) -> io::Result<()> {
    let json = serde_json::to_string(rules)?;
    fs::write(RULES_FILE, json)?;
    Ok(())
}

fn load_rules() -> io::Result<Vec<Rule>> {
    let path = Path::new(RULES_FILE);
    if path.exists() {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let rules = serde_json::from_str(&contents)?;
        Ok(rules)
    } else {
        Ok(Vec::new())  // Return an empty vector if the file does not exist
    }
}


fn main() {
    let loaded_rules = load_rules().unwrap_or_else(|e| {
        eprintln!("Failed to load rules: {}", e);
        Vec::new()
    });

    *RULES.lock().unwrap() = loaded_rules;

    loop {
        display_menu();
    }
}

fn start_firewall() {
    let interfaces = datalink::interfaces();
    let interface_names: Vec<String> = interfaces.iter()
        .map(|iface| iface.name.clone())
        .collect();

    if interface_names.is_empty() {
        println!("No available network interfaces found.");
        return;
    }

    // Clean logs when starting the firewall
    clean_logs();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a network interface to monitor")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = interface_names.get(selection).unwrap().clone();
    println!("Starting firewall on interface: {}", selected_interface);

    FIREWALL_RUNNING.store(true, Ordering::SeqCst);
    thread::spawn(move || {
        process_packets(selected_interface);
    });
}

fn clean_logs() {
    match File::create("firewall.log") {
        Ok(_) => println!("Logs have been cleaned."),
        Err(e) => eprintln!("Failed to clean logs: {}", e),
    }
}

fn stop_firewall() {
    FIREWALL_RUNNING.store(false, Ordering::SeqCst);
    println!("Firewall stopped.");
}

fn check_firewall_status() {
    if FIREWALL_RUNNING.load(Ordering::SeqCst) {
        println!("Firewall status: Running");
    } else {
        println!("Firewall status: Stopped");
    }
}

fn display_menu() {
    let items = vec![
        "View Rules", "Add Rule", "Remove Rule", "View Logs", "Clean Logs",
        "Start Firewall", "Stop Firewall", "Check Firewall Status",
        "Exit"
    ];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action")
        .default(0)
        .items(&items)
        .interact()
        .unwrap();

    match items[selection] {
        "View Rules" => view_rules(),
        "Add Rule" => add_rule(),
        "Remove Rule" => remove_rule(),
        "View Logs" => view_logs(),
        "Clean Logs" => clean_logs(),
        "Start Firewall" => start_firewall(),
        "Stop Firewall" => stop_firewall(),
        "Check Firewall Status" => check_firewall_status(),
        "Exit" => std::process::exit(0),
        _ => (),
    }
}

fn view_rules() {
    let rules = RULES.lock().unwrap();
    for (index, rule) in rules.iter().enumerate() {
        println!("{}: {:?}", index, rule);
    }
}

fn add_rule() {
    let protocol: String = Input::new()
        .with_prompt("Enter protocol (e.g., 'tcp', 'udp')")
        .interact_text()
        .unwrap();

    let source_ip: String = Input::new()
        .with_prompt("Enter source IP (leave empty if not applicable)")
        .default("".into())
        .interact_text()
        .unwrap();

    let destination_ip: String = Input::new()
        .with_prompt("Enter destination IP (leave empty if not applicable)")
        .default("".into())
        .interact_text()
        .unwrap();

    let source_port: u16 = Input::new()
        .with_prompt("Enter source port (leave empty if not applicable)")
        .default(0)
        .interact_text()
        .unwrap();

    let destination_port: u16 = Input::new()
        .with_prompt("Enter destination port (leave empty if not applicable)")
        .default(0)
        .interact_text()
        .unwrap();

    let actions = vec!["Allow", "Block"];
    let action = Select::new()
        .with_prompt("Choose action")
        .default(0)
        .items(&actions)
        .interact()
        .unwrap();

    let new_rule = Rule {
        id: Uuid::new_v4().to_string(),
        protocol,
        source_ip: if source_ip.is_empty() { None } else { Some(source_ip) },
        destination_ip: if destination_ip.is_empty() { None } else { Some(destination_ip) },
        source_port: if source_port == 0 { None } else { Some(source_port) },
        destination_port: if destination_port == 0 { None } else { Some(destination_port) },
        action: actions[action].to_lowercase(),
    };

    let mut rules = RULES.lock().unwrap();

    rules.push(new_rule.clone());

    save_rules(&rules).expect("Failed to save rules");

    // IMPORTANT: Update Linux IP Tables
    update_iptables(&new_rule.clone(), &new_rule.clone().action);

    println!("Rule added.");
}

fn update_iptables(rule: &Rule, action: &str) {
    let protocol = &rule.protocol;
    let source_ip = rule.source_ip.as_ref().map_or("".to_string(), |ip| format!("--source {}", ip));
    let destination_ip = rule.destination_ip.as_ref().map_or("".to_string(), |ip| format!("--destination {}", ip));
    let source_port = rule.source_port.map_or("".to_string(), |port| format!("--sport {}", port));
    let destination_port = rule.destination_port.map_or("".to_string(), |port| format!("--dport {}", port));
    let target = if action == "block" { "DROP" } else { "ACCEPT" };

    // Construct the iptables command as a string
    let iptables_command = format!("sudo iptables -A INPUT -p {} {} {} {} {} -j {} -m comment --comment {}",
                                   protocol, source_ip, destination_ip, source_port, destination_port, target, &rule.id);

    // Print the executed command for debugging purposes
    println!("Executing command: {}", iptables_command);

    // Execute the iptables command
    let output = Command::new("sh")
        .arg("-c")
        .arg(&iptables_command)
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute iptables command");

    if output.status.success() {
        println!("Rule updated in iptables.");
    } else {
        // Print the raw error message from stderr
        let stderr_output = String::from_utf8_lossy(&output.stderr);
        eprintln!("Failed to update rule in iptables. Error: {}", stderr_output);
    }
}

fn remove_rule() {
    // Get the rule descriptions and selection
    let (selected_rule_id, selection) = {
        let rules = RULES.lock().unwrap();
        let rule_descriptions: Vec<String> = rules.iter().map(|rule| format!("{:?}", rule)).collect();

        if rule_descriptions.is_empty() {
            println!("No rules to remove.");
            return;
        }

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a rule to remove")
            .default(0)
            .items(&rule_descriptions)
            .interact()
            .unwrap();

        // Clone the ID to use outside the lock scope
        let selected_rule_id = rules[selection].id.clone();
        (selected_rule_id, selection)
    };

    // Now we can remove the iptables rule outside the lock scope
    remove_iptables_rule(&selected_rule_id);

    // Now remove the rule from the application
    let mut rules = RULES.lock().unwrap();

    rules.remove(selection);

    println!("Rule removed.");
}


fn remove_iptables_rule(rule_id: &str) {
    // Construct the iptables command as a string
    let iptables_command = format!(
        "sudo iptables -L INPUT --line-numbers | grep -E '{}' | awk '{{print $1}}' | xargs -I {{}} sudo iptables -D INPUT {{}}",
        rule_id
    );

    // Print the executed command for debugging purposes
    println!("Executing command: {}", iptables_command);

    // Execute the iptables command
    let output = Command::new("sh")
        .arg("-c")
        .arg(&iptables_command)
        .output()
        .expect("Failed to execute iptables command");

    // Print the output of the executed command for debugging
    println!("Command output: {:?}", output);

    if output.status.success() {
        println!("Successfully removed iptables rule for rule ID: {}", rule_id);
    } else {
        eprintln!("Error removing iptables rule for rule ID: {}", rule_id);
    }
}

fn view_logs() {
    println!("Firewall Logs:");
    match fs::read_to_string("firewall.log") {
        Ok(contents) => println!("{}", contents),
        Err(e) => println!("Error reading log file: {}", e),
    }
}

fn process_packets(interface_name: String) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Error finding interface");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    while FIREWALL_RUNNING.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(packet) => {
                if let Some(tcp_packet) = TcpPacket::new(packet) {
                    process_tcp_packet(&tcp_packet);
                }
            },
            Err(e) => eprintln!("An error occurred while reading packet: {}", e),
        }
    }
}

fn process_tcp_packet(tcp_packet: &TcpPacket) {

    let rules = RULES.lock().unwrap();
    for rule in rules.iter() {
        if packet_matches_rule(tcp_packet, rule) {
            println!("Rule matched");
            match rule.action.as_str() {
                "block" => {
                    log_packet_action(tcp_packet, "Blocked");
                    return; // Dropping the packet
                },
                _ => (),
            }
        }
    }

    log_packet_action(tcp_packet, "Allowed");
    // Further processing or forwarding the packet
}

fn packet_matches_rule(packet: &TcpPacket, rule: &Rule) -> bool {
    // First, extract the IPv4 packet from the TCP packet
    if let Some(ipv4_packet) = Ipv4Packet::new(packet.packet()) {

        // Check protocol (assuming TCP, as we are working with TcpPacket)
        if rule.protocol.to_lowercase() != "tcp" {
            return false;
        }

        // Check source IP
        if let Some(ref rule_src_ip) = rule.source_ip {
            if ipv4_packet.get_source().to_string() != *rule_src_ip {
                return false;
            }
        }

        // Check destination IP
        if let Some(ref rule_dst_ip) = rule.destination_ip {
            if ipv4_packet.get_destination().to_string() != *rule_dst_ip {
                return false;
            }
        }

        // Check source port
        if let Some(rule_src_port) = rule.source_port {
            if packet.get_source() != rule_src_port {
                return false;
            }
        }

        // Check destination port
        if let Some(rule_dst_port) = rule.destination_port {
            if packet.get_destination() != rule_dst_port {
                return false;
            }
        }

        // If all checks pass, the packet matches the rule
        return true;
    }

    false
}

// Log packet action (either to console or to a file)
fn log_packet_action(packet: &TcpPacket, action: &str) {
    let log_message = format!("{} packet: {:?}, action: {}\n", action, packet, action);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("firewall.log")
        .unwrap();

    if let Err(e) = writeln!(file, "{}", log_message) {
        eprintln!("Couldn't write to log file: {}", e);
    }
}
