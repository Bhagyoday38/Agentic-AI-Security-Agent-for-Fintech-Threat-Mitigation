# app/services/simulation.py
import asyncio
import logging
import os
import sys
from typing import Optional

from ..api.websocket import manager
from ..config import settings  # Import settings

logger = logging.getLogger("Runner." + __name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SIMULATOR_SCRIPT_NAME = "attack_simulation.py"
SIMULATOR_SCRIPT_PATH = os.path.join(PROJECT_ROOT, SIMULATOR_SCRIPT_NAME)


async def run_simulation_background_task():
    """
    Runs the ethical attack simulator as a background task. Logs output.
    Uses absolute path, forces UTF-8, and broadcasts status via WebSocket.
    """
    logger.info("Received request to start background attack simulation...")
    target_url = "http://127.0.0.1:8000"

    if not os.path.isfile(SIMULATOR_SCRIPT_PATH):
        errmsg = f"Attack simulation script not found at: {SIMULATOR_SCRIPT_PATH}"
        logger.error(errmsg)
        await manager.broadcast({"type": "simulation_status", "status": "error", "message": f"Error: Script '{SIMULATOR_SCRIPT_NAME}' not found."})
        return

    # --- UPDATED COMMAND ---
    # We need to send MORE than the DOS_ATTACK_THRESHOLD (which is 50)
    # Let's send 75 requests (25 req/sec for 3 sec)
    dos_rate_per_sec = 25
    dos_duration = 3  # 25 * 3 = 75 requests. This is > 50.
    brute_force_attempts = 5  # Ensure we trigger the 3-attempt threshold
    # The 'count' arg is used for non-DoS attacks
    # The attack_simulation.py script uses 'count' for brute force, but we'll override it.

    command = [
        sys.executable, "-X", "utf8", SIMULATOR_SCRIPT_PATH, target_url,
        "--test-type", "all",
        # For Brute Force / Carding / etc.
        "--count", str(brute_force_attempts),
        "--dos-rate", str(dos_rate_per_sec),
        "--duration", str(dos_duration)
    ]
    # --- END UPDATED COMMAND ---

    process = None
    stdout_decoded = ""
    stderr_decoded = ""
    exit_code = -1
    stdout: Optional[bytes] = b''
    stderr: Optional[bytes] = b''

    try:
        logger.info(f"Running simulation command: {' '.join(command)}")
        await manager.broadcast({"type": "simulation_status", "status": "running", "message": "Attack simulation initiated..."})

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.info(
            f"Simulation subprocess started (PID: {process.pid}). Waiting for completion...")

        stdout, stderr = await process.communicate()
        exit_code = process.returncode
        logger.info(
            f"Simulation subprocess (PID: {process.pid}) finished with exit code {exit_code}.")
        stdout_decoded = stdout.decode(
            'utf-8', 'ignore').strip() if stdout else ""
        stderr_decoded = stderr.decode(
            'utf-8', 'ignore').strip() if stderr else ""

    except FileNotFoundError:
        errmsg = f"Failed to start simulation: Python executable '{sys.executable}' not found."
        logger.error(errmsg)
        await manager.broadcast({"type": "simulation_status", "status": "error", "message": errmsg})
        if stderr:
            stderr_decoded = stderr.decode('utf-8', 'ignore').strip()
    except Exception as e:
        pid_info = f"(PID: {process.pid})" if process else "(Process not started)"
        errmsg = f"An unexpected error occurred running simulation subprocess {pid_info}: {e}"
        logger.error(errmsg, exc_info=True)
        await manager.broadcast({"type": "simulation_status", "status": "error", "message": f"Error running simulation: {e}"})
        if stderr:
            stderr_decoded = stderr.decode('utf-8', 'ignore').strip()

    finally:
        log_pid = process.pid if process else 'N/A'
        if stdout_decoded:
            logger.info(
                f"Attack Simulation STDOUT (PID: {log_pid}, Exit: {exit_code}):\n------\n{stdout_decoded}\n------")
        else:
            logger.info(
                f"Attack Simulation STDOUT (PID: {log_pid}, Exit: {exit_code}): [No Output]")

        if stderr_decoded:
            log_level = logging.WARNING  # Log STDERR as Warning, not Error, if exit code is 0
            if exit_code != 0:
                log_level = logging.ERROR
            logger.log(
                log_level, f"Attack Simulation STDERR (PID: {log_pid}, Exit: {exit_code}):\n------\n{stderr_decoded}\n------")
        elif exit_code != 0 and exit_code != -1:
            logger.error(
                f"Attack Simulation STDERR (PID: {log_pid}, Exit: {exit_code}): [No Output, abnormal exit]")

        if exit_code != -1:  # Process was at least started
            if exit_code == 0:
                message = "Simulation finished successfully." + \
                    (" Check server logs for details (STDERR)." if stderr_decoded else "")
                await manager.broadcast({"type": "simulation_status", "status": "completed", "message": message})
            else:
                await manager.broadcast({"type": "simulation_status", "status": "failed", "message": f"Simulation failed (Code {exit_code}). See server logs."})
