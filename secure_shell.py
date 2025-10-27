import subprocess
import ctypes
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.url_checker import is_malicious_url, extract_urls_from_command, command_might_contain_url


def is_dangerous_by_ai(response):
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
        "⚠️ Dangerous Command Detected\n\n"
        f"Command:\n{command}\n\n"
        f"Reason:\n{reason}\n\n"
        "Do you want to CONTINUE?"
    )
    choice = ctypes.windll.user32.MessageBoxW(0, text, "Guardrail Alert", 1)
    return choice == 1  # 1 = OK, 2 = Cancel

def execute_command(command: str):
    """Run the actual command in the shell."""
    try:
        subprocess.run(command, shell=True)
    except (subprocess.SubprocessError, OSError) as e:
        log_event(event_type="SECURE_SHELL_EXEC_ERROR", message="{command} | Error: {error}", command=command, error=e)
        print(f"[ERROR] Execution failed: {e}")

def shell_loop():
    log_event(event_type="SECURE_SHELL_START", message="Secure Shell started.")
    while True:
        try:
            command = input("C:\\> ").strip()
            if not command:
                continue
            if command.lower() in ("exit", "quit"):
                print("Exiting Secure Shell.")
                log_event(event_type="SECURE_SHELL_EXIT", message="User exited Secure Shell.")
                break

            log_event(event_type="CMD_INPUT", message=command)

            # Only check for malicious URLs if the command might contain URLs
            if command_might_contain_url(command):
                # Extract URLs from the command
                urls = extract_urls_from_command(command)
                for url in urls:
                    if is_malicious_url(url):
                        log_event(event_type="CMD_MALICIOUS_URL", message="{command} | Malicious URL detected: {url}", command=command, url=url)
                        if not show_block_popup(command, f"Malicious URL detected: {url}"):
                            log_event(event_type="CMD_BLOCKED", message="{command} blocked due to malicious URL", command=command)
                            print("[Guardrail] Command blocked due to malicious URL.\n")
                            continue
                        else:
                            log_event(event_type="CMD_URL_ALLOWED", message="{command} URL check overridden by user", command=command)

            # Single AI call expecting a dict
            ai_result = analyze_text(f"CMD: {command}")
            log_event(event_type="CMD_AI_RESPONSE", message="{command} | AI: {ai_result}", command=command, ai_result=ai_result)

            # Determine if dangerous
            is_dangerous, reason = is_dangerous_by_ai(ai_result)

            if is_dangerous:
                log_event(event_type="CMD_FLAGGED", message="{command} | Reason: {reason}", command=command, reason=reason)
                if not show_block_popup(command, reason):
                    log_event(event_type="CMD_BLOCKED", message="{command} blocked by user", command=command)
                    print("[Guardrail] Command blocked.\n")
                    continue
                else:
                    log_event(event_type="CMD_ALLOWED", message="{command} allowed by user", command=command)

            else:
                log_event(event_type="CMD_SAFE", message="{command} deemed safe", command=command)

            # Execute if safe or allowed
            execute_command(command)

        except KeyboardInterrupt:
            print("\n[Guardrail] KeyboardInterrupt received. Use 'exit' to quit.")
            continue
        except (RuntimeError, OSError) as e:
            log_event(event_type="SECURE_SHELL_ERROR", message="{error}", error=str(e))
            print(f"[Guardrail Error] {e}")

if __name__ == "__main__":
    shell_loop()