import subprocess
import ctypes
from ai.mistral_analysis import analyze_text
from utils.logger import log_event

def is_dangerous_by_ai(response) -> (bool, str):
    """
    Determine danger from AI response.
    - If response is dict and has DANGEROUS=True, return (True, reason).
    - Otherwise treat as safe.
    """
    # If the AI returned a structured dict:
    if isinstance(response, dict):
        if response.get("DANGEROUS") is True:
            return True, response.get("reason", "No reason provided.")
        return False, ""

    # Fallback: if a plain string is returned
    if isinstance(response, str):
        lower = response.lower()
        # minimal fallback indicators
        for word in ("this command is dangerous", "can cause harm"):
            if word in lower:
                return True, response
    return False, ""

def show_block_popup(command: str, reason: str) -> bool:
    """
    Show a blocking popup.
    Returns True if user chooses CONTINUE (OK), False if BLOCK (Cancel).
    """
    text = (
        f"⚠️ Dangerous Command Detected\n\n"
        f"Command:\n{command}\n\n"
        f"Reason:\n{reason}\n\n"
        f"Do you want to CONTINUE?"
    )
    choice = ctypes.windll.user32.MessageBoxW(0, text, "Guardrail Alert", 1)
    return choice == 1  # 1 = OK, 2 = Cancel

def execute_command(command: str):
    """Run the actual command in the shell."""
    try:
        subprocess.run(command, shell=True)
    except Exception as e:
        log_event("SECURE_SHELL_EXEC_ERROR", f"{command} | Error: {e}")
        print(f"[ERROR] Execution failed: {e}")

def shell_loop():
    log_event("SECURE_SHELL_START", "Secure Shell started.")
    while True:
        try:
            command = input("C:\\> ").strip()
            if not command:
                continue
            if command.lower() in ("exit", "quit"):
                print("Exiting Secure Shell.")
                log_event("SECURE_SHELL_EXIT", "User exited Secure Shell.")
                break

            log_event("CMD_INPUT", command)

            # Single AI call expecting a dict
            ai_result = analyze_text(f"CMD: {command}")
            log_event("CMD_AI_RESPONSE", f"{command} | AI: {ai_result}")

            # Determine if dangerous
            is_dangerous, reason = is_dangerous_by_ai(ai_result)

            if is_dangerous:
                log_event("CMD_FLAGGED", f"{command} | Reason: {reason}")
                if not show_block_popup(command, reason):
                    log_event("CMD_BLOCKED", f"{command} blocked by user")
                    print("[Guardrail] Command blocked.\n")
                    continue
                else:
                    log_event("CMD_ALLOWED", f"{command} allowed by user")

            else:
                log_event("CMD_SAFE", f"{command} deemed safe")

            # Execute if safe or allowed
            execute_command(command)

        except KeyboardInterrupt:
            print("\n[Guardrail] KeyboardInterrupt received. Use 'exit' to quit.")
            continue
        except Exception as e:
            log_event("SECURE_SHELL_ERROR", str(e))
            print(f"[Guardrail Error] {e}")

if __name__ == "__main__":
    shell_loop()
