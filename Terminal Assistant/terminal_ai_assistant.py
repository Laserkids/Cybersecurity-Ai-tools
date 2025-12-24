#!/usr/bin/env python3
"""
AI Terminal Assistant - Cross-platform terminal helper with Ollama integration
Compatible with Kali Linux and Windows
Features: Auto-start Ollama, Command analysis, AI chat window, cancel commands, project summaries
"""

import os
import sys
import subprocess
import json
import requests
import platform
import threading
import signal
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, ttk

class AIChat:
    """Separate AI chat window"""
    def __init__(self, ollama_host, os_type, session_log_ref):
        self.ollama_host = ollama_host
        self.os_type = os_type
        self.session_log_ref = session_log_ref
        self.chat_history = []
        self.window = None
        
    def query_ollama(self, prompt):
        """Send query to Ollama"""
        try:
            url = f"{self.ollama_host}/api/generate"
            
            # Build context from recent commands
            recent_commands = []
            if self.session_log_ref:
                recent_commands = [entry['command'] for entry in self.session_log_ref[-5:]]
            
            context = f"""You are a helpful terminal assistant AI.
Operating System: {self.os_type}
Recent commands executed: {', '.join(recent_commands) if recent_commands else 'None yet'}

Answer questions about terminal commands, debugging, and help with the user's work."""
            
            data = {
                "model": "llama3.2",
                "prompt": f"{context}\n\nUser: {prompt}\nAssistant:",
                "stream": False
            }
            response = requests.post(url, json=data, timeout=60)
            if response.status_code == 200:
                return response.json()["response"]
            return "Error: Could not get response from Ollama"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def send_message(self):
        """Send message to AI"""
        user_msg = self.input_box.get("1.0", tk.END).strip()
        if not user_msg:
            return
        
        # Clear input
        self.input_box.delete("1.0", tk.END)
        
        # Display user message
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"You: {user_msg}\n\n", "user")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
        # Show thinking indicator
        self.status_label.config(text="AI is thinking...")
        self.window.update()
        
        # Get AI response
        response = self.query_ollama(user_msg)
        
        # Display AI response
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"AI: {response}\n\n", "ai")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
        self.status_label.config(text="Ready")
        
        # Log chat
        self.chat_history.append({
            "timestamp": datetime.now().isoformat(),
            "user": user_msg,
            "ai": response
        })
    
    def create_window(self):
        """Create chat window"""
        self.window = tk.Tk()
        self.window.title("AI Terminal Assistant - Chat")
        self.window.geometry("600x500")
        
        # Configure colors
        bg_color = "#1e1e1e"
        fg_color = "#ffffff"
        input_bg = "#2d2d2d"
        
        self.window.configure(bg=bg_color)
        
        # Header
        header = tk.Label(
            self.window, 
            text=f"🤖 AI Chat Assistant ({self.os_type})",
            font=("Arial", 14, "bold"),
            bg=bg_color,
            fg=fg_color
        )
        header.pack(pady=10)
        
        # Chat display
        chat_frame = tk.Frame(self.window, bg=bg_color)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=input_bg,
            fg=fg_color,
            insertbackground=fg_color,
            state=tk.DISABLED
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for styling
        self.chat_display.tag_config("user", foreground="#4ec9b0")
        self.chat_display.tag_config("ai", foreground="#dcdcaa")
        
        # Input frame
        input_frame = tk.Frame(self.window, bg=bg_color)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_label = tk.Label(
            input_frame,
            text="Your message:",
            bg=bg_color,
            fg=fg_color,
            font=("Arial", 9)
        )
        input_label.pack(anchor=tk.W)
        
        self.input_box = tk.Text(
            input_frame,
            height=3,
            font=("Consolas", 10),
            bg=input_bg,
            fg=fg_color,
            insertbackground=fg_color
        )
        self.input_box.pack(fill=tk.X, pady=5)
        
        # Bind Enter key (Shift+Enter for new line)
        self.input_box.bind("<Return>", lambda e: self.handle_enter(e))
        
        # Button frame
        button_frame = tk.Frame(self.window, bg=bg_color)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        send_button = tk.Button(
            button_frame,
            text="Send (Enter)",
            command=self.send_message,
            bg="#0e639c",
            fg=fg_color,
            font=("Arial", 10, "bold"),
            cursor="hand2"
        )
        send_button.pack(side=tk.LEFT, padx=5)
        
        clear_button = tk.Button(
            button_frame,
            text="Clear Chat",
            command=self.clear_chat,
            bg="#3c3c3c",
            fg=fg_color,
            font=("Arial", 10)
        )
        clear_button.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = tk.Label(
            self.window,
            text="Ready - Ask me anything about your terminal work!",
            bg=bg_color,
            fg="#888888",
            font=("Arial", 8)
        )
        self.status_label.pack(pady=5)
        
        # Welcome message
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, 
            "AI: Hello! I'm your terminal assistant. Ask me questions while you work!\n"
            "I can help with:\n"
            "- Explaining commands\n"
            "- Debugging errors\n"
            "- Suggesting solutions\n"
            "- General terminal help\n\n",
            "ai"
        )
        self.chat_display.config(state=tk.DISABLED)
        
        self.window.mainloop()
    
    def handle_enter(self, event):
        """Handle Enter key press"""
        if event.state & 0x1:  # Shift is pressed
            return  # Allow new line
        else:
            self.send_message()
            return "break"  # Prevent default behavior
    
    def clear_chat(self):
        """Clear chat display"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete("1.0", tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def run(self):
        """Run chat window in thread"""
        self.create_window()


class TerminalAIAssistant:
    def __init__(self, ollama_host="http://localhost:11434"):
        self.ollama_host = ollama_host
        self.os_type = platform.system()
        self.session_log = []
        self.project_name = "terminal_session"
        self.output_dir = Path("ai_terminal_outputs")
        self.output_dir.mkdir(exist_ok=True)
        self.current_process = None
        self.cancelled = False
        self.ollama_process = None
        
    def check_ollama(self):
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def start_ollama_server(self):
        """Start the Ollama server"""
        print("🚀 Starting Ollama server...")
        
        try:
            if self.os_type == "Windows":
                # On Windows, try to start Ollama
                try:
                    # Try to start ollama serve in background
                    self.ollama_process = subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                except FileNotFoundError:
                    print("❌ Ollama not found. Please install from https://ollama.com/download")
                    return False
            else:
                # On Linux/Mac
                try:
                    # Try to start ollama serve in background
                    self.ollama_process = subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=os.setpgrp if hasattr(os, 'setpgrp') else None
                    )
                except FileNotFoundError:
                    print("❌ Ollama not found. Install with: curl -fsSL https://ollama.com/install.sh | sh")
                    return False
            
            # Wait for server to start (max 15 seconds)
            print("⏳ Waiting for Ollama to initialize...")
            for i in range(15):
                time.sleep(1)
                if self.check_ollama():
                    print("✓ Ollama server started successfully!")
                    return True
                sys.stdout.write(f"\rWaiting... {i+1}/15 seconds")
                sys.stdout.flush()
            
            print("\n⚠️  Ollama server started but not responding. Continuing anyway...")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start Ollama: {str(e)}")
            return False
    
    def check_llama_model(self):
        """Check if llama3.2 model is installed"""
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                for model in models:
                    if 'llama3.2' in model.get('name', '').lower():
                        return True
            return False
        except:
            return False
    
    def install_llama_model(self):
        """Install llama3.2 model"""
        print("\n📦 Installing llama3.2 model (this may take a few minutes)...")
        try:
            process = subprocess.Popen(
                ["ollama", "pull", "llama3.2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Show progress
            for line in process.stdout:
                print(line.rstrip())
            
            process.wait()
            
            if process.returncode == 0:
                print("✓ llama3.2 model installed successfully!")
                return True
            else:
                print("❌ Failed to install llama3.2 model")
                return False
                
        except Exception as e:
            print(f"❌ Error installing model: {str(e)}")
            return False
    
    def query_ollama(self, prompt, context=""):
        """Send query to Ollama"""
        try:
            url = f"{self.ollama_host}/api/generate"
            data = {
                "model": "llama3.2",
                "prompt": f"{context}\n\n{prompt}",
                "stream": False
            }
            response = requests.post(url, json=data, timeout=30)
            if response.status_code == 200:
                return response.json()["response"]
            return None
        except Exception as e:
            return f"Error querying Ollama: {str(e)}"
    
    def analyze_command(self, command):
        """Analyze a command before execution"""
        context = f"Operating System: {self.os_type}\nYou are a terminal assistant analyzing commands."
        prompt = f"""Analyze this command and provide:
1. What it does
2. Potential risks or mistakes
3. Suggestions for improvement

Command: {command}

Be concise and practical."""
        
        return self.query_ollama(prompt, context)
    
    def execute_command(self, command):
        """Execute a command safely with cancel support"""
        self.cancelled = False
        try:
            if self.os_type == "Windows":
                self.current_process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                self.current_process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    executable='/bin/bash',
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
            
            stdout, stderr = self.current_process.communicate(timeout=30)
            returncode = self.current_process.returncode
            
            if self.cancelled:
                return {
                    "success": False,
                    "stdout": stdout,
                    "stderr": "Command cancelled by user",
                    "returncode": -999
                }
            
            return {
                "success": returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": returncode
            }
        except subprocess.TimeoutExpired:
            self.cancel_command()
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out after 30 seconds",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    
    def cancel_command(self):
        """Cancel the currently running command"""
        self.cancelled = True
        if self.current_process:
            try:
                if self.os_type == "Windows":
                    self.current_process.kill()
                else:
                    # Kill entire process group on Unix
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
                    else:
                        self.current_process.kill()
                print("\n⚠️  Command cancelled!")
            except:
                pass
    
    def log_command(self, command, analysis, result):
        """Log command execution"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "analysis": analysis,
            "result": result
        }
        self.session_log.append(entry)
    
    def generate_summary(self):
        """Generate project summary"""
        if not self.session_log:
            return "No commands executed in this session."
        
        commands_list = "\n".join([f"- {entry['command']}" for entry in self.session_log])
        
        prompt = f"""Analyze this terminal session and provide:
1. Project Overview: What was the user trying to accomplish?
2. Commands Summary: Brief explanation of what was done
3. Potential Issues: Any problems or mistakes identified
4. Recommendations: Suggestions for improvement

Commands executed:
{commands_list}

Provide a clear, structured summary."""
        
        context = f"Operating System: {self.os_type}\nTotal commands: {len(self.session_log)}"
        return self.query_ollama(prompt, context)
    
    def save_summary(self):
        """Save session summary to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"summary_{timestamp}.txt"
        
        summary = self.generate_summary()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{'='*60}\n")
            f.write(f"AI Terminal Assistant - Session Summary\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Operating System: {self.os_type}\n")
            f.write(f"Total Commands: {len(self.session_log)}\n\n")
            f.write(f"{'='*60}\n")
            f.write(f"AI ANALYSIS\n")
            f.write(f"{'='*60}\n\n")
            f.write(summary)
            f.write(f"\n\n{'='*60}\n")
            f.write(f"DETAILED LOG\n")
            f.write(f"{'='*60}\n\n")
            
            for i, entry in enumerate(self.session_log, 1):
                f.write(f"[{i}] {entry['timestamp']}\n")
                f.write(f"Command: {entry['command']}\n")
                f.write(f"Analysis: {entry['analysis']}\n")
                f.write(f"Result: {'Success' if entry['result']['success'] else 'Failed'}\n")
                if entry['result']['stdout']:
                    f.write(f"Output: {entry['result']['stdout'][:200]}...\n")
                if entry['result']['stderr']:
                    f.write(f"Error: {entry['result']['stderr'][:200]}...\n")
                f.write("\n" + "-"*60 + "\n\n")
        
        return filename
    
    def start_chat_window(self):
        """Start the AI chat window in a separate thread"""
        chat = AIChat(self.ollama_host, self.os_type, self.session_log)
        chat_thread = threading.Thread(target=chat.run, daemon=True)
        chat_thread.start()
        return chat_thread
    
    def cleanup(self):
        """Cleanup on exit"""
        if self.ollama_process:
            try:
                print("\n🛑 Stopping Ollama server...")
                if self.os_type == "Windows":
                    self.ollama_process.terminate()
                else:
                    self.ollama_process.terminate()
                self.ollama_process.wait(timeout=5)
            except:
                pass
    
    def interactive_mode(self):
        """Run in interactive mode"""
        print("="*60)
        print("AI Terminal Assistant")
        print(f"OS: {self.os_type}")
        print("="*60)
        
        # Check if Ollama is running, if not start it
        if not self.check_ollama():
            print("\n⚠️  Ollama is not running")
            if not self.start_ollama_server():
                print("\n❌ Could not start Ollama server")
                response = input("Continue without Ollama? (y/n): ")
                if response.lower() != 'y':
                    return
            else:
                # Check if model is installed
                print("\n🔍 Checking for llama3.2 model...")
                if not self.check_llama_model():
                    print("⚠️  llama3.2 model not found")
                    response = input("Install llama3.2 model now? (y/n): ")
                    if response.lower() == 'y':
                        self.install_llama_model()
                    else:
                        print("⚠️  AI features may not work without the model")
                else:
                    print("✓ llama3.2 model is ready")
        else:
            print("\n✓ Ollama is already running")
            # Still check for model
            if not self.check_llama_model():
                print("⚠️  llama3.2 model not found")
                response = input("Install llama3.2 model now? (y/n): ")
                if response.lower() == 'y':
                    self.install_llama_model()
        
        # Start chat window
        print("\n✓ Starting AI chat window...")
        self.start_chat_window()
        
        print("\nCommands:")
        print("  Type commands to analyze and execute")
        print("  'analyze <command>' - Only analyze without executing")
        print("  'cancel' - Cancel currently running command")
        print("  'summary' - Generate session summary")
        print("  'save' - Save summary to file")
        print("  'exit' - Exit the assistant")
        print("\n💬 AI Chat window opened - Ask questions while you work!")
        print("\n" + "="*60 + "\n")
        
        try:
            while True:
                try:
                    command = input(f"{self.os_type}> ").strip()
                    
                    if not command:
                        continue
                    
                    if command.lower() == 'exit':
                        print("\nGenerating final summary...")
                        filename = self.save_summary()
                        print(f"✓ Summary saved to: {filename}")
                        print("Goodbye!")
                        break
                    
                    if command.lower() == 'cancel':
                        self.cancel_command()
                        continue
                    
                    if command.lower() == 'summary':
                        print("\nGenerating summary...\n")
                        summary = self.generate_summary()
                        print(summary)
                        print()
                        continue
                    
                    if command.lower() == 'save':
                        filename = self.save_summary()
                        print(f"✓ Summary saved to: {filename}\n")
                        continue
                    
                    if command.lower().startswith('analyze '):
                        cmd = command[8:].strip()
                        print("\n🔍 Analyzing command...\n")
                        analysis = self.analyze_command(cmd)
                        print(analysis)
                        print()
                        continue
                    
                    # Analyze and execute
                    print("\n🔍 Analyzing command...\n")
                    analysis = self.analyze_command(command)
                    print(analysis)
                    
                    proceed = input("\n⚡ Execute command? (y/n/cancel): ")
                    if proceed.lower() == 'y':
                        print("\n⚙️  Executing... (type 'cancel' in next prompt to stop)\n")
                        result = self.execute_command(command)
                        
                        if result['stdout']:
                            print(result['stdout'])
                        if result['stderr'] and result['returncode'] != -999:
                            print(f"Error: {result['stderr']}", file=sys.stderr)
                        
                        self.log_command(command, analysis, result)
                        
                        if result['returncode'] == -999:
                            print("⚠️  Command was cancelled")
                        elif result['success']:
                            print("✓ Command completed successfully")
                        else:
                            print(f"✗ Command failed with code {result['returncode']}")
                    elif proceed.lower() == 'cancel':
                        print("Command execution cancelled.")
                    print()
                    
                except KeyboardInterrupt:
                    print("\n\n⚠️  Interrupted! Type 'exit' to quit or continue working...")
                    print("(Current command cancelled if running)\n")
                    self.cancel_command()
                except Exception as e:
                    print(f"Error: {str(e)}\n")
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    assistant = TerminalAIAssistant()
    assistant.interactive_mode()

if __name__ == "__main__":
    main()