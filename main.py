import os
import pickle
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from collections import Counter
import re
import time
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these SCOPES, delete the file token.pickle.
# Using .modify scope now to allow for trashing emails.
# You will likely need to delete your 'token.pickle' file and re-authenticate.
SCOPES = ['https://mail.google.com/']

class GmailApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gmail Advanced")
        self.root.geometry("1000x800")
        
        self.service = None
        self.user_email = None

        self.setup_styles()
        self.create_login_ui()

    def setup_styles(self):
        self.bg_color = '#f0f0f0'
        self.content_bg = '#ffffff'
        self.text_color = '#333333'
        self.header_font = ('Arial', 16, 'bold')
        self.label_font = ('Arial', 12)
        self.small_font = ('Arial', 10)

        self.root.configure(bg=self.bg_color)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=self.label_font)
        style.configure('Header.TLabel', font=self.header_font, background=self.bg_color)
        style.configure('TButton', font=self.label_font, background='#e0e0e0', foreground=self.text_color)
        style.map('TButton', background=[('active', '#d0d0d0')])
        style.configure('Treeview', background=self.content_bg, foreground=self.text_color, fieldbackground=self.content_bg, font=self.small_font, rowheight=25)
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', font=('Arial', 12), padding=[10, 5], background='#e0e0e0')
        style.map('TNotebook.Tab', background=[('selected', self.bg_color)])

    def create_login_ui(self):
        self.login_frame = ttk.Frame(self.root, padding="50")
        self.login_frame.pack(expand=True)

        ttk.Label(self.login_frame, text="Gmail Advanced", font=('Arial', 24, 'bold')).pack(pady=20)
        
        self.login_button = ttk.Button(self.login_frame, text="Login with Gmail", command=self.login)
        self.login_button.pack(pady=10)

        self.status_label = ttk.Label(self.login_frame, text="Not logged in", font=self.small_font)
        self.status_label.pack(pady=5)

    def login(self):
        self.login_button.config(state='disabled')
        self.status_label.config(text="Authenticating...")
        threading.Thread(target=self._login_thread, daemon=True).start()

    def _login_thread(self):
        try:
            self.service = self._get_gmail_service()
            if self.service:
                profile = self.service.users().getProfile(userId='me').execute()
                self.user_email = profile['emailAddress']
                self.root.after(0, self.on_login_success)
            else:
                self.root.after(0, self.on_login_failed)
        except Exception as e:
            self.root.after(0, lambda: self.on_login_failed(str(e)))

    def _get_gmail_service(self):
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    self.root.after(0, lambda: messagebox.showerror("Error", "credentials.json file not found!"))
                    return None
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        return build('gmail', 'v1', credentials=creds)

    def on_login_success(self):
        self.login_frame.destroy()
        self.create_main_ui()
        self.load_stats_data()

    def on_login_failed(self, error=""):
        self.status_label.config(text=f"Login Failed. {error}")
        self.login_button.config(state='normal')

    def create_main_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)

        stats_tab = ttk.Frame(notebook, padding=10)
        search_tab = ttk.Frame(notebook)
        clean_tab = ttk.Frame(notebook)

        notebook.add(stats_tab, text='Stats')
        notebook.add(search_tab, text='Search')
        notebook.add(clean_tab, text='Clean')

        self.create_stats_tab(stats_tab)
        self.create_clean_tab(clean_tab)

    def create_stats_tab(self, parent):
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        # Total Emails
        total_emails_frame = ttk.Frame(parent, style='Card.TFrame')
        total_emails_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        ttk.Label(total_emails_frame, text="Total Emails:", font=self.header_font).pack(side='left', padx=10, pady=10)
        self.total_emails_label = ttk.Label(total_emails_frame, text="Loading...", font=self.header_font)
        self.total_emails_label.pack(side='left', padx=10, pady=10)

        # Labels/Folders Stats
        labels_frame = ttk.Frame(parent)
        labels_frame.grid(row=1, column=0, sticky='nsew', padx=(0, 5))
        ttk.Label(labels_frame, text="Emails per Label/Folder", font=self.header_font).pack(pady=(0,5), anchor='w')
        
        labels_tree_frame = ttk.Frame(labels_frame)
        labels_tree_frame.pack(fill='both', expand=True)
        self.labels_tree = ttk.Treeview(labels_tree_frame, columns=('Label', 'Count'), show='headings')
        self.labels_tree.heading('Label', text='Label/Folder')
        self.labels_tree.heading('Count', text='Email Count')
        self.labels_tree.column('Count', anchor='center', width=120)
        self.labels_tree.pack(side='left', fill='both', expand=True)
        
        labels_scrollbar = ttk.Scrollbar(labels_tree_frame, orient='vertical', command=self.labels_tree.yview)
        self.labels_tree.configure(yscrollcommand=labels_scrollbar.set)
        labels_scrollbar.pack(side='right', fill='y')

        # Domain Stats
        domains_frame = ttk.Frame(parent)
        domains_frame.grid(row=1, column=1, sticky='nsew', padx=(5, 0))
        ttk.Label(domains_frame, text="Emails by Sender Domain", font=self.header_font).pack(pady=(0,5), anchor='w')
        
        domains_tree_frame = ttk.Frame(domains_frame)
        domains_tree_frame.pack(fill='both', expand=True)
        self.domains_tree = ttk.Treeview(domains_tree_frame, columns=('Domain', 'Count'), show='headings')
        self.domains_tree.heading('Domain', text='Domain')
        self.domains_tree.heading('Count', text='Email Count')
        self.domains_tree.column('Count', anchor='center', width=120)
        self.domains_tree.pack(side='left', fill='both', expand=True)
        
        domains_scrollbar = ttk.Scrollbar(domains_tree_frame, orient='vertical', command=self.domains_tree.yview)
        self.domains_tree.configure(yscrollcommand=domains_scrollbar.set)
        domains_scrollbar.pack(side='right', fill='y')

        # --- Full Analysis Controls ---
        analysis_controls_frame = ttk.Frame(parent)
        analysis_controls_frame.grid(row=2, column=1, sticky='ew', padx=(5, 0), pady=(10,0))

        self.start_analysis_button = ttk.Button(analysis_controls_frame, text="Start Full Domain Analysis", command=self.start_full_domain_analysis)
        self.start_analysis_button.pack(side='left', padx=(0, 10))

        self.cancel_analysis_button = ttk.Button(analysis_controls_frame, text="Cancel", command=self.cancel_full_analysis)
        self.cancel_analysis_button.pack(side='left')
        self.cancel_analysis_button.config(state='disabled')

        self.domain_progress = ttk.Progressbar(parent, orient='horizontal', mode='determinate')
        self.domain_progress.grid(row=3, column=1, sticky='ew', padx=(5, 0), pady=5)
        
        self.domain_status_label = ttk.Label(parent, text="Click 'Start Full Domain Analysis' to begin.", font=self.small_font)
        self.domain_status_label.grid(row=4, column=1, sticky='w', padx=(5, 0))

    def create_clean_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # --- Controls ---
        controls_frame = ttk.Frame(parent)
        controls_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))

        # Backup path
        backup_frame = ttk.Frame(controls_frame)
        backup_frame.pack(fill='x', pady=5, anchor='w')
        ttk.Label(backup_frame, text="Backup Location:").pack(side='left', padx=(0, 5))
        self.backup_path_var = tk.StringVar(value="No directory selected")
        ttk.Label(backup_frame, textvariable=self.backup_path_var, font=self.small_font, relief="sunken", padding=2).pack(side='left', fill='x', expand=True)
        ttk.Button(backup_frame, text="Select...", command=self.select_backup_path).pack(side='left', padx=(5, 0))

        # Action buttons
        action_frame = ttk.Frame(controls_frame)
        action_frame.pack(fill='x', pady=5, anchor='w')
        self.find_button = ttk.Button(action_frame, text="Find GitHub Notification Emails", command=self.find_github_emails)
        self.find_button.pack(side='left')
        self.delete_button = ttk.Button(action_frame, text="Backup & Delete Selected", command=self.backup_and_delete_emails, state='disabled')
        self.delete_button.pack(side='left', padx=(10,5))
        self.select_all_button = ttk.Button(action_frame, text="Select All", command=self.select_all_clean_tree, state='disabled')
        self.select_all_button.pack(side='left', padx=(0,5))
        self.deselect_all_button = ttk.Button(action_frame, text="Deselect All", command=self.deselect_all_clean_tree, state='disabled')
        self.deselect_all_button.pack(side='left')

        # --- Progress and Status ---
        progress_frame = ttk.Frame(parent)
        progress_frame.grid(row=1, column=0, sticky='ew', pady=(5, 0))
        self.clean_status_label = ttk.Label(progress_frame, text="Ready.", font=self.small_font)
        self.clean_status_label.pack(fill='x', expand=True, side='left')
        self.clean_progress = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate')
        self.clean_progress.pack(fill='x', expand=True, side='right', padx=10)

        # --- Results Treeview ---
        results_frame = ttk.Frame(parent)
        results_frame.grid(row=2, column=0, sticky='nsew', pady=(10,0))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        
        self.clean_tree = ttk.Treeview(results_frame, columns=('Subject', 'Date'), show='headings')
        self.clean_tree.heading('Subject', text='Subject')
        self.clean_tree.heading('Date', text='Date')
        self.clean_tree.column('Subject', width=400)
        self.clean_tree.column('Date', width=150)
        
        tree_scroll_y = ttk.Scrollbar(results_frame, orient='vertical', command=self.clean_tree.yview)
        tree_scroll_x = ttk.Scrollbar(results_frame, orient='horizontal', command=self.clean_tree.xview)
        self.clean_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        self.clean_tree.grid(row=0, column=0, sticky='nsew')
        tree_scroll_y.grid(row=0, column=1, sticky='ns')
        tree_scroll_x.grid(row=1, column=0, sticky='ew')

    def select_all_clean_tree(self):
        all_items = self.clean_tree.get_children()
        self.clean_tree.selection_set(all_items)

    def deselect_all_clean_tree(self):
        self.clean_tree.selection_remove(self.clean_tree.selection())

    def select_backup_path(self):
        path = filedialog.askdirectory()
        if path:
            self.backup_path_var.set(path)
            self.clean_status_label.config(text=f"Backup location set to: {path}")

    def find_github_emails(self):
        self.find_button.config(state='disabled')
        self.delete_button.config(state='disabled')
        self.select_all_button.config(state='disabled')
        self.deselect_all_button.config(state='disabled')
        self.clean_status_label.config(text="Finding emails...")
        for i in self.clean_tree.get_children():
            self.clean_tree.delete(i)
        threading.Thread(target=self._find_github_emails_thread, daemon=True).start()

    def _find_github_emails_thread(self):
        try:
            query = "from:notifications@github.com"
            all_message_infos = []
            page_token = None
            self.root.after(0, lambda: self.clean_status_label.config(text="Searching for emails..."))
            while True:
                response = self.service.users().messages().list(userId='me', q=query, pageToken=page_token, maxResults=500).execute()
                messages = response.get('messages', [])
                if messages:
                    all_message_infos.extend(messages)
                page_token = response.get('nextPageToken')
                self.root.after(0, lambda: self.clean_status_label.config(text=f"Found {len(all_message_infos)} matching emails so far..."))
                if not page_token:
                    break
            
            total_found = len(all_message_infos)
            if not total_found:
                self.root.after(0, lambda: self.clean_status_label.config(text="No emails found from notifications@github.com."))
                self.root.after(0, lambda: self.find_button.config(state='normal'))
                return
            
            email_details = []
            processed_count = [0]

            def metadata_callback(request_id, response, exception):
                processed_count[0] += 1
                if exception is None:
                    subject = next((h['value'] for h in response['payload']['headers'] if h['name'].lower() == 'subject'), 'No Subject')
                    date = next((h['value'] for h in response['payload']['headers'] if h['name'].lower() == 'date'), 'Unknown Date')
                    email_details.append((subject, date, response['id']))

                if processed_count[0] % 20 == 0 or processed_count[0] == total_found:
                    self.root.after(0, lambda: self.clean_status_label.config(text=f"Fetching details... {processed_count[0]}/{total_found}"))

            for i in range(0, total_found, 100):
                batch = self.service.new_batch_http_request(callback=metadata_callback)
                for msg_info in all_message_infos[i:i+100]:
                    batch.add(self.service.users().messages().get(userId='me', id=msg_info['id'], format='metadata', metadataHeaders=['Subject', 'Date']))
                batch.execute()
                time.sleep(1) 

            self.root.after(0, self.populate_clean_tree, email_details)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to find emails: {e}"))
            self.root.after(0, lambda: self.clean_status_label.config(text="Error finding emails."))
        finally:
            self.root.after(0, lambda: self.find_button.config(state='normal'))

    def populate_clean_tree(self, email_details):
        for i in self.clean_tree.get_children():
            self.clean_tree.delete(i)
        
        for subject, date, msg_id in email_details:
            self.clean_tree.insert('', 'end', values=(subject, date), iid=msg_id)
        
        count = len(email_details)
        self.clean_status_label.config(text=f"Found {count} emails. Select emails from the list, then click 'Backup & Delete'.")
        if email_details:
            self.delete_button.config(state='normal')
            self.select_all_button.config(state='normal')
            self.deselect_all_button.config(state='normal')

    def backup_and_delete_emails(self):
        selected_items = self.clean_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more emails from the list to delete.")
            return

        backup_path = self.backup_path_var.get()
        if not os.path.isdir(backup_path):
            messagebox.showerror("Invalid Path", "Please select a valid backup directory first.")
            return
            
        if messagebox.askyesno("Confirm Deletion", f"This will permanently move {len(selected_items)} email(s) to the Trash.\n\nAre you sure you want to continue?"):
            self.delete_button.config(state='disabled')
            self.find_button.config(state='disabled')
            self.select_all_button.config(state='disabled')
            self.deselect_all_button.config(state='disabled')
            self.clean_progress.config(maximum=len(selected_items), value=0)

            emails_to_process = []
            for msg_id in selected_items:
                values = self.clean_tree.item(msg_id)['values']
                subject = values[0] if values else "No Subject"
                emails_to_process.append({'id': msg_id, 'subject': subject})
            
            threading.Thread(target=self._backup_and_delete_thread, args=(emails_to_process, backup_path), daemon=True).start()

    def _backup_and_delete_thread(self, emails_to_process, backup_path):
        try:
            total_to_process = len(emails_to_process)
            email_map = {email['id']: email for email in emails_to_process}
            all_ids = list(email_map.keys())

            chunk_size = 100  # Process in chunks of 100
            chunks = [all_ids[i:i + chunk_size] for i in range(0, len(all_ids), chunk_size)]
            
            overall_processed_count = 0
            overall_successful_ids = []

            for id_chunk in chunks:
                # --- Batch Backup ---
                eml_contents = {}
                def backup_callback(request_id, response, exception):
                    if exception is None:
                        msg_id = response['id']
                        eml_data = base64.urlsafe_b64decode(response['raw'].encode('ASCII'))
                        eml_contents[msg_id] = eml_data
                    else:
                        print(f"Error in backup batch for request {request_id}: {exception}")

                backup_batch = self.service.new_batch_http_request(callback=backup_callback)
                for msg_id in id_chunk:
                    backup_batch.add(self.service.users().messages().get(userId='me', id=msg_id, format='raw'))
                backup_batch.execute()

                # --- Save files and collect IDs for deletion ---
                backed_up_ids_in_chunk = []
                for msg_id, eml_data in eml_contents.items():
                    try:
                        subject = email_map[msg_id]['subject']
                        sanitized_subject = re.sub(r'[\\/*?:"<>|]', "", subject)[:50]
                        filename = f"{msg_id}-{sanitized_subject}.eml"
                        filepath = os.path.join(backup_path, filename)
                        with open(filepath, 'wb') as f:
                            f.write(eml_data)
                        backed_up_ids_in_chunk.append(msg_id)
                    except Exception as e:
                        print(f"Failed to save file for {msg_id}: {e}")

                # --- Batch Delete ---
                if backed_up_ids_in_chunk:
                    self.service.users().messages().batchDelete(
                        userId='me',
                        body={'ids': backed_up_ids_in_chunk}
                    ).execute()
                    overall_successful_ids.extend(backed_up_ids_in_chunk)

                overall_processed_count += len(id_chunk)
                self.root.after(0, self.update_after_batch_delete, overall_processed_count, total_to_process, backed_up_ids_in_chunk)
                time.sleep(1) # Pause between chunks to be safe

            self.root.after(0, lambda: self.clean_status_label.config(text=f"Successfully backed up and moved {len(overall_successful_ids)} emails to Trash."))
        except HttpError as error:
            if error.resp.status == 403:
                self.root.after(0, lambda: messagebox.showerror(
                    "Permission Denied",
                    "The application does not have permission to delete emails.\n\n"
                    "This is likely because the permissions have been updated. Please:\n"
                    "1. Close this application.\n"
                    "2. Delete the 'token.pickle' file in your project directory.\n"
                    "3. Relaunch the app and re-authorize it."
                ))
                self.root.after(0, lambda: self.clean_status_label.config(text="Permission denied. Please re-authenticate."))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", f"An API error occurred: {error}"))
                self.root.after(0, lambda: self.clean_status_label.config(text="An API error occurred. Some emails may not have been processed."))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred: {e}"))
            self.root.after(0, lambda: self.clean_status_label.config(text="An unexpected error occurred. Some emails may not have been processed."))
        finally:
            self.root.after(0, lambda: self.find_button.config(state='normal'))
            self.root.after(0, lambda: self.delete_button.config(state='normal' if self.clean_tree.get_children() else 'disabled'))
            self.root.after(0, lambda: self.select_all_button.config(state='normal' if self.clean_tree.get_children() else 'disabled'))
            self.root.after(0, lambda: self.deselect_all_button.config(state='normal' if self.clean_tree.get_children() else 'disabled'))
            self.root.after(0, lambda: self.clean_progress.config(value=0))

    def update_after_batch_delete(self, processed_count, total_to_process, deleted_ids):
        self.clean_progress.config(value=processed_count)
        self.clean_status_label.config(text=f"Processing... {processed_count}/{total_to_process}")
        for msg_id in deleted_ids:
            if self.clean_tree.exists(msg_id):
                self.clean_tree.delete(msg_id)

    def load_stats_data(self):
        threading.Thread(target=self._load_stats_thread, daemon=True).start()

    def start_full_domain_analysis(self):
        self.start_analysis_button.config(state='disabled')
        self.cancel_analysis_button.config(state='normal')
        self.cancel_analysis = False
        threading.Thread(target=self._full_analysis_thread, daemon=True).start()

    def cancel_full_analysis(self):
        self.cancel_analysis = True
        self.cancel_analysis_button.config(state='disabled')
        self.domain_status_label.config(text="Cancellation signal sent...")

    def _full_analysis_thread(self):
        try:
            # Phase 1: Get all message IDs
            self.root.after(0, lambda: self.domain_status_label.config(text="Fetching all message IDs... This may take a while."))
            all_messages = []
            page_token = None
            while True:
                if self.cancel_analysis:
                    self.root.after(0, self.on_analysis_finished, True)
                    return
                
                response = self.service.users().messages().list(userId='me', pageToken=page_token, maxResults=500).execute()
                all_messages.extend(response.get('messages', []))
                page_token = response.get('nextPageToken')
                
                self.root.after(0, lambda: self.domain_status_label.config(text=f"Fetching message IDs... Found {len(all_messages):,}"))

                if not page_token:
                    break
            
            total_messages = len(all_messages)
            self.root.after(0, lambda: self.domain_progress.config(maximum=total_messages, value=0))

            if not all_messages:
                self.root.after(0, self.on_analysis_finished)
                return

            # Phase 2: Process in batches
            domain_counter = Counter()
            processed_count = [0]
            email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+')

            def full_analysis_callback(request_id, response, exception):
                processed_count[0] += 1
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
                    email_match = email_pattern.search(from_header)
                    if email_match:
                        email_address = email_match.group(0)
                        if '@' in email_address:
                            domain = email_address.split('@')[-1]
                            domain_counter[domain] += 1
                
                if processed_count[0] % 20 == 0 or processed_count[0] == total_messages:
                    self.root.after(0, self.update_analysis_progress, processed_count[0], total_messages)

            for i in range(0, total_messages, 100):
                if self.cancel_analysis:
                    break 

                batch = self.service.new_batch_http_request(callback=full_analysis_callback)
                for msg in all_messages[i:i+100]:
                    batch.add(self.service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']))
                batch.execute()
                time.sleep(1) # Add delay to avoid hitting rate limits
            
            self.root.after(0, self.update_domains_tree, domain_counter.most_common())
            self.root.after(0, self.on_analysis_finished, self.cancel_analysis)

        except Exception as e:
            print(f"Error during full analysis: {e}")
            self.root.after(0, lambda: self.domain_status_label.config(text=f"Error: {e}"))
            self.root.after(0, self.on_analysis_finished, True)

    def update_analysis_progress(self, processed, total):
        self.domain_progress.config(value=processed)
        self.domain_status_label.config(text=f"Analyzing email {processed:,} / {total:,}...")

    def on_analysis_finished(self, cancelled=False):
        if cancelled:
            self.domain_status_label.config(text="Analysis stopped.")
        else:
            total_count = self.domain_progress['maximum']
            self.domain_status_label.config(text=f"Full analysis of {total_count:,} emails complete.")
        
        self.start_analysis_button.config(state='normal')
        self.cancel_analysis_button.config(state='disabled')
        self.domain_progress.config(value=0)

    def _load_stats_thread(self):
        # Fetch total emails
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            total_messages = profile.get('messagesTotal', 'N/A')
            self.root.after(0, lambda: self.total_emails_label.config(text=f"{total_messages:,}"))
        except Exception as e:
            self.root.after(0, lambda: self.total_emails_label.config(text="Error"))
            print(f"Error fetching total emails: {e}")

        # Fetch label stats
        try:
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            label_stats = []
            for label in labels:
                # Some system labels like 'CHAT' don't have message counts in list response
                if 'messagesTotal' in label:
                    count = label.get('messagesTotal', 0)
                else: # Fallback to get individual label details
                    try:
                        label_details = self.service.users().labels().get(userId='me', id=label['id']).execute()
                        count = label_details.get('messagesTotal', 0)
                    except Exception:
                        count = 0 # Or 'N/A' if preferred
                
                label_stats.append((label['name'], count))
            
            label_stats.sort(key=lambda x: x[1], reverse=True)
            self.root.after(0, self.update_labels_tree, label_stats)
        except Exception as e:
            print(f"Error fetching label stats: {e}")

        # Fetch domain stats from recent emails
        try:
            self.root.after(0, lambda: self.domain_status_label.config(text="Fetching recent emails for preview..."))
            response = self.service.users().messages().list(userId='me', maxResults=500).execute()
            messages = response.get('messages', [])
            total_messages = len(messages)

            if not messages:
                self.root.after(0, lambda: self.domain_status_label.config(text="No recent emails to preview."))
                return

            domain_counter = Counter()
            processed_count = [0]
            email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+')

            def domain_stats_callback(request_id, response, exception):
                processed_count[0] += 1
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
                    
                    email_match = email_pattern.search(from_header)
                    if email_match:
                        email_address = email_match.group(0)
                        if '@' in email_address:
                            domain = email_address.split('@')[-1]
                            domain_counter[domain] += 1
                else:
                    print(f"Error in batch request for message: {exception}")

                if processed_count[0] == total_messages:
                    domain_stats = domain_counter.most_common()
                    self.root.after(0, self.update_domains_tree, domain_stats)
                    self.root.after(0, lambda: self.domain_status_label.config(text=f"Preview complete. Found {len(domain_stats)} domains in recent emails."))
                else:
                    self.root.after(0, lambda: self.domain_status_label.config(text=f"Analyzing email {processed_count[0]}/{total_messages} for preview..."))

            # Process messages in batches of 100
            for i in range(0, total_messages, 100):
                batch = self.service.new_batch_http_request(callback=domain_stats_callback)
                for msg in messages[i:i+100]:
                    batch.add(self.service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']))
                batch.execute()

        except Exception as e:
            print(f"Error fetching domain stats: {e}")
            self.root.after(0, lambda: self.domain_status_label.config(text="Error loading domain stats preview."))

    def update_labels_tree(self, label_stats):
        for item in self.labels_tree.get_children():
            self.labels_tree.delete(item)
        for label, count in label_stats:
            self.labels_tree.insert('', 'end', values=(label, f"{count:,}"))

    def update_domains_tree(self, domain_stats):
        for item in self.domains_tree.get_children():
            self.domains_tree.delete(item)
        for domain, count in domain_stats:
            self.domains_tree.insert('', 'end', values=(domain, count))

def main():
    root = tk.Tk()
    app = GmailApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
