# attack_simulation.py (in project root)
import requests
import time
import json
import random
import argparse
from datetime import datetime
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional
import sys
import traceback
import asyncio
import httpx

print(f"[SimScript] Started execution at {datetime.now().isoformat()}")

BRUTE_FORCE_IP = "10.10.10.1"
CARD_TESTING_IP = "10.10.10.2"


class EthicalAttackSimulator:
    def __init__(self, target_url: str, api_endpoint: str = "/log_event", check_connection: bool = True):
        print("[SimScript] Initializing EthicalAttackSimulator...")
        self.target_url = target_url.rstrip('/')
        self.api_endpoint = api_endpoint
        self.full_url = urljoin(self.target_url, self.api_endpoint)
        self.session = requests.Session()
        self.attack_log = []
        print(f"[SimScript] Target log endpoint: {self.full_url}")

        self.attack_templates = {
            "sqli": {"display_name": "SQL Injection", "event_type": "simulated_sql_injection", "severity": "HIGH", "description": "Ethical SQL injection test", "payloads": [{"username": "admin' OR '1'='1--", "password": "pw"}, {"query": "'; SELECT pg_sleep(1); --"}, {"id": "1 UNION SELECT null, version(), null--"}, ]},
            "xss": {"display_name": "XSS", "event_type": "simulated_xss", "severity": "HIGH", "description": "Ethical XSS test", "payloads": [{"comment": "<script>console.log('SimulatedXSS')</script>"}, {"search": "\"><img src=x onerror=console.error('SimulatedXSS')>"}, {"profile": "javascript:console.warn('SimulatedXSS')"}, ]},
            "payment": {"display_name": "Payment Anomaly", "event_type": "simulated_payment_anomaly", "severity": "MEDIUM", "description": "Ethical payment anomaly test", "payloads": [{"card_number": f"4242-4242-4242-{random.randint(1000, 9999)}", "cvv": f"{random.randint(100, 999)}", "expiry_date": "12/28", "amount": "9999.99", "currency": "USD"}, {"payment_token": f"tok_{random.randbytes(12).hex()}", "amount": "5001.00", "currency": "EUR"}, ]},
            "card_testing": {"display_name": "Card Testing", "event_type": "payment_failure", "severity": "CRITICAL", "description": "Ethical card testing simulation", "payloads": [{"card_bin": "411111", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Insufficient Funds"}, {"card_bin": "510510", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Invalid CVV"}, {"card_bin": "400000", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Do Not Honor"}, {"card_bin": "411111", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Expired Card"}, {"card_bin": "555555", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Generic Decline"}, ]}
        }

        base_target_url = self.target_url
        if check_connection:
            try:
                print(
                    f"[SimScript] Checking reachability of base target: {base_target_url}")
                response = self.session.get(base_target_url, timeout=3.0)
                print(
                    f"[SimScript] Target reachability check status: {response.status_code}")
            except requests.exceptions.Timeout:
                print(
                    f"[SimScript] WARNING: Timeout connecting to target {base_target_url}", file=sys.stderr)
            except requests.exceptions.ConnectionError as e:
                print(
                    f"[SimScript] WARNING: Could not connect to target {base_target_url}: {e}", file=sys.stderr)
            except Exception as e:
                print(
                    f"[SimScript] WARNING: An unexpected error occurred reaching target {base_target_url}: {e}", file=sys.stderr)
        else:
            print("[SimScript] Skipping connection check during dummy initialization.")
        print("[SimScript] Simulator Initialized.")

    def log_attack_locally(self, attack_data: Dict[str, Any]):
        attack_data['timestamp'] = datetime.now().isoformat()
        self.attack_log.append(attack_data)

    def send_to_security_system(self, event_type: str, payload: Dict[str, Any], user_id: Optional[str] = None, custom_ip: Optional[str] = None) -> bool:
        event_data = {"event_type": event_type, "data": payload,
                      "source_ip": custom_ip or f"192.168.1.{random.randint(50, 150)}", "user_agent": f"EthicalSim/1.{random.randint(0, 2)}"}
        if user_id:
            event_data["user_id"] = user_id

        print(
            f"[SimScript] Attempting to send: {event_type} from IP {event_data['source_ip']} to {self.full_url}")
        try:
            response = self.session.post(self.full_url, json=event_data, headers={
                                         "Content-Type": "application/json"}, timeout=15.0)
            status_symbol = "[OK]" if 200 <= response.status_code < 300 else "[FAIL]"
            print(
                f"[SimScript] Sent: {event_type} -> {status_symbol} {response.status_code}")
            if not (200 <= response.status_code < 300):
                try:
                    error_detail = response.json()
                    print(
                        f"[SimScript] Server Response (Error {response.status_code}): {json.dumps(error_detail)}", file=sys.stderr)
                except json.JSONDecodeError:
                    print(
                        f"[SimScript] Server Response (Error {response.status_code}): {response.text[:200]}...", file=sys.stderr)
                return False
            return True
        except requests.exceptions.Timeout:
            print(
                f"[SimScript] ERROR sending {event_type}: Request timed out after 15s", file=sys.stderr)
            return False
        except requests.exceptions.ConnectionError as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Connection error - {e}", file=sys.stderr)
            return False
        except requests.exceptions.RequestException as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Network error - {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Unexpected error - {e}", file=sys.stderr)
            return False

    def simulate_attack_type(self, test_type: str, count: int, static_ip: Optional[str] = None):
        if test_type not in self.attack_templates:
            print(
                f"[SimScript] ERROR: Unknown test type: {test_type}", file=sys.stderr)
            return
        template = self.attack_templates[test_type]
        print(
            f"\n[SimScript] --- Simulating {count} '{template['display_name']}' Attacks ---")
        payload_list = template.get("payloads", [])
        if not payload_list:
            print("[SimScript] WARNING: No payloads defined.")
            return
        success_count = 0
        for i in range(count):
            payload_index = i % len(
                payload_list) if test_type == "card_testing" else random.randrange(len(payload_list))
            payload = payload_list[payload_index]
            print(f"[SimScript]   Test {i+1}/{count}: Preparing payload...")
            self.log_attack_locally({"attack_type": template['display_name'], "payload": payload,
                                    "severity": template['severity'], "description": template['description']})
            if self.send_to_security_system(template['event_type'], payload, custom_ip=static_ip):
                success_count += 1
            time.sleep(random.uniform(0.3, 0.6))
        print(
            f"[SimScript] --- Finished '{template['display_name']}'. Sent successfully: {success_count}/{count} ---")

    def simulate_brute_force(self, user_id: str, attempts: int, static_ip: Optional[str] = None):
        passwords = ["123456", "password", "admin",
                     "qwerty", f"pass{random.randint(10, 99)}"]
        print(
            f"\n[SimScript] --- Simulating {attempts} Brute Force Attempts on '{user_id}' ---")
        success_count = 0
        for i in range(attempts):
            password = random.choice(passwords)
            print(
                f"[SimScript]   Attempt {i+1}/{attempts}: User '{user_id}', Pass '*****'")
            self.log_attack_locally({"attack_type": "Brute Force", "payload": {
                                    "username": user_id, "password": "[MASKED]"}, "severity": "MEDIUM", "user_id": user_id, "description": f"Attempt {i+1}"})
            if self.send_to_security_system("login_failure", {"username": user_id, "password": password}, user_id, custom_ip=static_ip):
                success_count += 1
            time.sleep(random.uniform(0.2, 0.5))
        print(
            f"[SimScript] --- Finished Brute Force. Sent successfully: {success_count}/{attempts} ---")

    async def _send_dos_request(self, client: httpx.AsyncClient, session_id: int, req_id: int):
        payload = {"req_id": f"{session_id}-{req_id}", "ts": time.time()}
        event_data = {"event_type": "simulated_high_traffic", "data": payload,
                      "source_ip": f"10.20.{random.randint(1, 254)}.{random.randint(1, 254)}", "user_agent": f"EthicalSim/DoS"}
        try:
            response = await client.post(self.full_url, json=event_data, headers={"Content-Type": "application/json"})
            return 200 <= response.status_code < 300
        except Exception:
            return False

    async def simulate_dos_async(self, requests_per_second: int, duration: int):
        print(
            f"\n[SimScript] --- Simulating DoS Traffic ({requests_per_second} req/sec for {duration}s) ---")
        total_to_send = requests_per_second * duration
        if total_to_send <= 0:
            print("[SimScript] DoS duration or rate is 0. Skipping.")
            return
        print(f"[SimScript] Total requests to send: {total_to_send}")
        start_time = time.time()
        session_id = random.randint(1000, 9999)

        async with httpx.AsyncClient(timeout=5.0) as client:
            tasks = []
            sleep_interval = duration / total_to_send if total_to_send > 0 else 0
            for i in range(total_to_send):
                tasks.append(self._send_dos_request(client, session_id, i))
                if sleep_interval > 0.001:
                    await asyncio.sleep(sleep_interval)

            print(f"[SimScript] Launching {len(tasks)} DoS requests...")
            results = await asyncio.gather(*tasks, return_exceptions=False)

            success_count = sum(1 for r in results if r is True)
            fail_count = len(results) - success_count
            print(
                f"[SimScript] --- DoS simulation finished in {time.time() - start_time:.2f}s. Success: {success_count}, Failed/Timed Out: {fail_count} ---")

    async def run_comprehensive_test_async(self, count_per_type: int, brute_force_attempts: int, dos_duration: int, dos_rate: int):
        print("\n" + "=" * 60)
        print("   [SimScript] Starting Comprehensive Simulation")
        print(f"   [SimScript] Target API: {self.full_url}")
        print("=" * 60 + "\n")
        # Run synchronous parts
        for test_type in self.attack_templates:
            if test_type == "card_testing":
                # Send card testing from a static IP (use 'count' arg)
                self.simulate_attack_type(
                    test_type, count_per_type, static_ip=CARD_TESTING_IP)
            else:
                self.simulate_attack_type(
                    test_type, count_per_type, static_ip=f"192.168.1.{random.randint(50, 150)}")

        self.simulate_brute_force(
            "simulated_victim", brute_force_attempts, static_ip=BRUTE_FORCE_IP)
        await self.simulate_dos_async(requests_per_second=dos_rate, duration=dos_duration)
        print("\n" + "=" * 60)
        print("   [SimScript] Simulation Completed")
        print(
            f"   [SimScript] Total non-DoS events attempted: {len(self.attack_log)}")
        print("=" * 60 + "\n")


def main():
    print("[SimScript] main() function started.")
    parser = argparse.ArgumentParser(description="Ethical Attack Simulator")

    try:
        _attack_choices = list(EthicalAttackSimulator(
            "http://localhost:1", api_endpoint='/', check_connection=False).attack_templates.keys())
    except Exception:
        _attack_choices = ["sqli", "xss", "payment", "card_testing"]

    parser.add_argument(
        "target_url", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("--test-type", choices=["all"] + _attack_choices + [
                        "brute", "dos"], default="all", help="Type of test")
    parser.add_argument("--count", type=int, default=5,
                        help="Attacks per type / Brute attempts")  # Default 5
    parser.add_argument("--dos-rate", type=int, default=50,
                        help="DoS requests per second (default: 50)")
    parser.add_argument("--user-id", default="sim_user_main",
                        help="User ID for brute force")
    parser.add_argument("--duration", type=int, default=3,
                        help="DoS duration (seconds)")
    args = parser.parse_args()
    print(f"[SimScript] Arguments parsed: {args}")

    print("\n" + "+" + "-" * 66 + "+")
    print("|" + " " * 18 + "ETHICAL ATTACK SIMULATOR v1.3" + " " * 19 + "|")
    print("|" + " " * 16 + "For Authorized Security Testing Only" + " " * 16 + "|")
    print("+" + "-" * 66 + "+")
    print(
        "\n[SimScript] WARNING: Ensure you have explicit permission before testing.\n")

    is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
    print(f"[SimScript] Interactive mode detected: {is_interactive}")
    proceed = False
    if is_interactive:
        try:
            confirm = input(
                f"[SimScript] Target: {args.target_url}. Run '{args.test_type}' simulation? (y/N): ").lower()
            if confirm == 'y':
                proceed = True
            else:
                print("[SimScript] Simulation cancelled by user.")
                sys.exit(0)
        except EOFError:
            print(
                "[SimScript] WARNING: EOFError, assuming non-interactive and proceeding.", file=sys.stderr)
            proceed = True
        except Exception as e:
            print(
                f"[SimScript] ERROR reading confirmation: {e}. Aborting.", file=sys.stderr)
            sys.exit(1)
    else:
        print(
            f"[SimScript] Running non-interactively. Target: {args.target_url}, Test: {args.test_type}")
        proceed = True

    if not proceed:
        print("[SimScript] Simulation not started.")
        sys.exit(0)

    print("[SimScript] Initializing simulator instance with actual target...")
    simulator = EthicalAttackSimulator(args.target_url, check_connection=True)
    print("[SimScript] Simulator instance created.")

    try:
        print(f"[SimScript] Starting test type: {args.test_type}")
        if args.test_type == "all":
            asyncio.run(simulator.run_comprehensive_test_async(
                count_per_type=args.count,
                brute_force_attempts=args.count,  # Use --count
                dos_duration=args.duration,
                dos_rate=args.dos_rate
            ))
        elif args.test_type in simulator.attack_templates:
            if args.test_type == "card_testing":
                simulator.simulate_attack_type(
                    args.test_type, args.count, static_ip=CARD_TESTING_IP)
            else:
                simulator.simulate_attack_type(args.test_type, args.count)
        elif args.test_type == "brute":
            simulator.simulate_brute_force(
                args.user_id, args.count, static_ip=BRUTE_FORCE_IP)
        elif args.test_type == "dos":
            asyncio.run(simulator.simulate_dos_async(
                requests_per_second=args.dos_rate, duration=args.duration))
        print("\n[SimScript] Simulation script finished successfully.")
    except Exception as e:
        print(
            f"\n[SimScript] ERROR: Simulation script failed during execution: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    print("[SimScript] Script invoked directly.")
    main()
