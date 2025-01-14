import os
import pickle
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from collections import defaultdict

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service(log_callback):
    """Sets up and returns the Gmail service object."""
    creds = None

    log_callback("Checking for token.pickle...")
    # Load existing credentials if available
    if os.path.exists('token.pickle'):
        log_callback("Found token.pickle, loading credentials...")
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    else:
        log_callback("No token.pickle found.")

    # If credentials are invalid or don't exist, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            log_callback("Refreshing expired credentials...")
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                msg = (
                    "Error: credentials.json not found in the current folder.\n"
                    "Please place your OAuth client credentials file here."
                )
                log_callback(msg)
                raise FileNotFoundError(msg)

            log_callback("Running local server flow to get new credentials...")
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save credentials for future use
        log_callback("Saving new credentials to token.pickle...")
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    log_callback("Building Gmail service object...")
    service = build('gmail', 'v1', credentials=creds)
    log_callback("Gmail service is ready.")
    return service

def get_emails_by_sender(service, max_results=500, log_callback=None):
    """Fetches emails and groups them by sender."""
    if log_callback:
        log_callback("Requesting up to {} emails from Gmail...".format(max_results))

    emails_by_sender = defaultdict(list)
    
    # Get list of messages
    results = service.users().messages().list(
        userId='me', 
        maxResults=max_results
    ).execute()
    
    messages = results.get('messages', [])
    if log_callback:
        log_callback("Fetched {} message metadata entries.".format(len(messages)))

    for i, message in enumerate(messages):
        if log_callback and i % 50 == 0 and i > 0:
            log_callback(f"Processed {i} emails so far...")

        # Get full message details
        msg = service.users().messages().get(
            userId='me', 
            id=message['id'],
            format='metadata',
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        
        # Extract headers
        headers = msg['payload']['headers']
        sender = next(
            (header['value'] for header in headers if header['name'] == 'From'),
            'Unknown'
        )
        subject = next(
            (header['value'] for header in headers if header['name'] == 'Subject'),
            'No Subject'
        )
        date = next(
            (header['value'] for header in headers if header['name'] == 'Date'),
            'No Date'
        )
        
        # Store email info
        emails_by_sender[sender].append({
            'subject': subject,
            'date': date,
            'id': message['id']
        })
    
    if log_callback:
        log_callback("Grouping complete. Found {} unique senders.".format(len(emails_by_sender)))
    return emails_by_sender

class EmailAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gmail Analyzer")
        self.root.geometry("900x700")

        # Configure root window
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        # Main frame
        self.main_frame = ttk.Frame(root, padding="10", relief="solid", borderwidth=1)
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Logging text frame
        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=5)
        
        # Initialize email data and service
        self.emails_by_sender = None
        self.service = None
        
        self.create_widgets()
        
        # Grid weights inside main_frame
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(1, weight=1)  # For the TreeView
        self.main_frame.rowconfigure(2, weight=1)  # For the detail_text
        self.main_frame.rowconfigure(3, weight=1)  # For the log frame

    def create_widgets(self):
        # Load button
        self.load_button = ttk.Button(
            self.main_frame, 
            text="Load Emails", 
            command=self.load_emails_thread
        )
        self.load_button.grid(row=0, column=0, pady=10, sticky="w")
        
        # Progress label
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(
            self.main_frame, 
            textvariable=self.progress_var
        )
        self.progress_label.grid(row=0, column=1, pady=10, padx=10)
        
        # Treeview for senders
        self.tree = ttk.Treeview(
            self.main_frame, 
            columns=("Sender", "Count"), 
            show="headings"
        )
        self.tree.heading("Sender", text="Sender")
        self.tree.heading("Count", text="Number of Emails")
        self.tree.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=5)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(
            self.main_frame, 
            orient=tk.VERTICAL, 
            command=self.tree.yview
        )
        scrollbar.grid(row=1, column=2, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Text widget for email details
        self.detail_text = tk.Text(
            self.main_frame, 
            height=8, 
            wrap=tk.WORD
        )
        self.detail_text.grid(
            row=2, column=0, columnspan=3, sticky="nsew", pady=5
        )
        
        # Log text widget
        self.log_text = tk.Text(self.log_frame, height=8, wrap=tk.WORD, fg="blue")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Log scrollbar
        log_scrollbar = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        # Bind treeview selection
        self.tree.bind("<<TreeviewSelect>>", self.show_email_details)

    def log_message(self, msg):
        """Insert log messages into the log_text widget and print to console."""
        self.log_text.insert(tk.END, f"{msg}\n")
        self.log_text.see(tk.END)  # auto-scroll to the bottom
        print(msg)  # Also print to the console for debugging

    def load_emails_thread(self):
        """Start email loading in a separate thread."""
        self.log_message("Starting email load in background thread...")
        self.load_button.configure(state="disabled")
        self.progress_var.set("Loading emails...")
        
        thread = threading.Thread(target=self.load_emails)
        thread.daemon = True
        thread.start()

    def load_emails(self):
        """Load emails from Gmail."""
        try:
            if not self.service:
                self.log_message("No Gmail service yet. Connecting...")
                self.service = get_gmail_service(self.log_message)
            
            self.log_message("Service acquired. Now fetching emails...")
            self.emails_by_sender = get_emails_by_sender(
                self.service,
                max_results=500,
                log_callback=self.log_message
            )
            
            # Update UI in the main thread
            self.root.after(0, self.update_treeview)
            self.root.after(0, lambda: self.progress_var.set("Emails loaded successfully"))
            self.root.after(0, lambda: self.load_button.configure(state="normal"))
            self.log_message("Done fetching emails!")
            
        except Exception as e:
            err_str = f"Error loading emails: {e}"
            self.log_message(err_str)
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.load_button.configure(state="normal"))
            self.root.after(0, lambda: self.progress_var.set("Error loading emails"))

    def update_treeview(self):
        """Update the treeview with email data."""
        self.log_message("Updating treeview with new data...")
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.emails_by_sender:
            self.log_message("No emails_by_sender data to display.")
            return
        
        # Sort senders by email count
        sorted_senders = sorted(
            self.emails_by_sender.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        
        # Insert new items
        for sender, emails in sorted_senders:
            self.tree.insert(
                "", 
                "end", 
                values=(sender, len(emails))
            )

    def show_email_details(self, event):
        """Show details of selected sender's emails."""
        selection = self.tree.selection()
        if not selection:
            return
        
        sender = self.tree.item(selection[0])["values"][0]
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, f"Recent emails from {sender}:\n\n")
        
        emails = self.emails_by_sender[sender]
        
        # Display up to 5 recent emails
        for email in emails[:5]:
            self.detail_text.insert(tk.END, f"Subject: {email['subject']}\n")
            self.detail_text.insert(tk.END, f"Date: {email['date']}\n")
            self.detail_text.insert(tk.END, "-" * 50 + "\n\n")
        
        self.log_message(f"Displayed details for {sender}.")

def main():
    try:
        root = tk.Tk()
        app = EmailAnalyzerApp(root)
        root.mainloop()
    except Exception as e:
        print("Fatal error:", e)
        messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    main()
