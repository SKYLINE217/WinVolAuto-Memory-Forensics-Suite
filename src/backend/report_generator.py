import json
import os
import datetime
import hashlib
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch

import re

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
        # Plugin descriptions for the report
        self.plugin_descriptions = {
            "windows.pslist": "Lists all processes running on the system. This plugin traverses the list of active process structures in the kernel memory. It is useful for identifying running applications and system services.",
            "windows.psscan": "Scans physical memory for process objects (EPROCESS). Unlike pslist, this can detect 'hidden' processes that have been unlinked from the OS process list (DKOM attacks).",
            "windows.pstree": "Displays processes in a tree structure, showing parent-child relationships. This helps identify suspicious spawning behavior (e.g., cmd.exe spawned by a web browser).",
            "windows.netscan": "Scans for network artifacts (TCP/UDP endpoints, listeners). Critical for identifying Command & Control (C2) connections.",
            "windows.malfind": "Scans for hidden or injected code in user mode memory (VADs). It looks for memory pages that are executable but not backed by a file on disk, a common indicator of malware injection.",
            "windows.dlllist": "Lists loaded DLLs for each process. Useful for finding malicious libraries injected into legitimate processes.",
            "windows.handles": "Lists open handles (files, registry keys, mutexes) for processes.",
            "windows.cmdline": "Recovers command line arguments used to start processes. This often reveals malicious scripts or flags used by attackers.",
            "windows.callbacks": "Enumerates kernel-mode callback registrations; anomalies can indicate rootkit behavior.",
            "windows.svcscan": "Lists Windows services and binaries; unusual locations (Temp/AppData) signal persistence.",
            "windows.filescan": "Carves memory for file objects to identify accessed files during the capture.",
            "windows.modules": "Lists loaded kernel modules; checks for unexpected or unsigned drivers.",
            "windows.driverscan": "Scans memory for driver objects potentially missed by standard enumeration.",
            "windows.registry.hivelist": "Enumerates registry hives in memory for subsequent key analysis.",
            "windows.registry.printkey": "Prints registry key contents to investigate autoruns or configuration.",
            "windows.getservicesids": "Maps service accounts to SIDs for privilege and identity investigation.",
            "windows.getsids": "Lists process SIDs to detect unusual identities or impersonation.",
            "linux.pslist": "Lists running processes on Linux systems.",
            "linux.bash": "Recovers bash history from memory, potentially showing commands typed by an attacker.",
            "linux.check_syscall": "Checks the system call table for hooks, a common rootkit technique.",
            "linux.elfs": "Enumerates loaded ELF binaries and modules for anomalies.",
            "mac.pslist": "Lists macOS processes to establish baseline activity.",
            "mac.bash": "Recovers macOS bash history entries from memory.",
            "mac.check_syscall": "Checks macOS syscall table for signs of hooks.",
            "banners.Banners": "Scans memory for OS version banners and potential configuration strings.",
            "internal.win.cmdline": "WinVolAuto internal: summarizes suspicious command lines (encoded, web calls).",
            "internal.win.pstree": "WinVolAuto internal: highlights orphan processes and risky parent-child pairs.",
            "internal.win.kernel_scan": "WinVolAuto internal: summarises kernel callbacks that may indicate hooks.",
            "internal.win.persistence_scan": "WinVolAuto internal: flags services loading from Temp/AppData paths.",
            "internal.linux.pslist": "WinVolAuto internal: triages Linux processes, flags /tmp exec and root shells.",
            "internal.linux.bash": "WinVolAuto internal: summarises risky bash history commands.",
            "internal.linux.check_syscall": "WinVolAuto internal: counts syscall hooks indicating rootkits.",
            "internal.linux.elfs": "WinVolAuto internal: flags ELF modules loaded from /tmp or /dev/shm.",
            "internal.win.text_scan": "WinVolAuto internal: identifies text-like files from memory, previews content, and summarizes folder distribution.",
        }

    def setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor('#003366')
        ))
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leftIndent=20,
            textColor=colors.black
        ))
        self.styles.add(ParagraphStyle(
            name='TableText',
            parent=self.styles['Normal'],
            fontSize=8,  # Reduced font size
            wordWrap='CJK',
            alignment=TA_LEFT,
            leading=10   # Tighter line spacing
        ))

    def _inject_wrapping_space(self, text, interval=10):
        """
        Injects a standard space every `interval` characters 
        into long words to force wrapping in PDF.
        We use a standard space because zero-width space (\u200b) is not 
        supported by standard PDF fonts and renders as a black square.
        """
        if not text:
            return ""
        text = str(text)
        # Split by existing spaces to preserve them
        words = text.split(' ')
        processed_words = []
        for word in words:
            if len(word) > interval:
                # Insert space every 'interval' chars
                chunks = [word[i:i+interval] for i in range(0, len(word), interval)]
                processed_words.append(' '.join(chunks))
            else:
                processed_words.append(word)
        return ' '.join(processed_words)

    def _get_file_hash(self, file_path):
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read only first 64MB to be fast for report
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "Unable to calculate hash (File locked or inaccessible)"

    def generate_json(self, results, risk_report, file_path, filename="analysis_report.json", capabilities=None):
        report = {
            "metadata": {
                "generated_at": str(datetime.datetime.now()),
                "file_analyzed": file_path,
                "file_name": os.path.basename(file_path) if file_path else "Unknown"
            },
            "risk_analysis": risk_report,
            "results": results,
            "malware_capabilities": capabilities or []
        }
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w') as f:
            json.dump(report, f, indent=4)
        return path

    def generate_pdf(self, results, risk_report, file_path, filename="analysis_report.pdf", capabilities=None):
        # Use Landscape for more width (11 inches total, ~10 inches usable)
        doc = SimpleDocTemplate(
            os.path.join(self.output_dir, filename),
            pagesize=landscape(letter),
            rightMargin=36, leftMargin=36,  # Smaller margins for max space
            topMargin=36, bottomMargin=36
        )
        
        story = []
        
        # --- Title Page ---
        story.append(Paragraph("FORENSIC ANALYSIS REPORT", self.styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("WinVolAuto Professional Suite", self.styles['Heading2']))
        story.append(Spacer(1, 30))
        
        # --- Case Information ---
        story.append(Paragraph("1. CASE INFORMATION", self.styles['SectionHeader']))
        
        file_name = os.path.basename(file_path) if file_path else "N/A"
        file_size = f"{os.path.getsize(file_path) / (1024*1024):.2f} MB" if file_path and os.path.exists(file_path) else "Unknown"
        # Skip hash for large files in UI thread, or do it? Let's just do name/size/date for speed.
        
        # Helper to create wrapped table cells with CJK wrapping
        def p_cell(text, style=self.styles['TableText']):
            # Inject spaces to force wrapping for long strings
            safe_text = self._inject_wrapping_space(text)
            return Paragraph(safe_text, style)

        case_data = [
            [p_cell("Analysis Date:", self.styles['Heading4']), p_cell(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))],
            [p_cell("Target File:", self.styles['Heading4']), p_cell(file_name)],
            [p_cell("File Path:", self.styles['Heading4']), p_cell(file_path if file_path else "N/A")],
            [p_cell("File Size:", self.styles['Heading4']), p_cell(file_size)],
            [p_cell("Analyst:", self.styles['Heading4']), p_cell("WinVolAuto Automated Agent")],
        ]
        
        # Landscape width ~10 inches.
        t = Table(case_data, colWidths=[2.0*inch, 8.0*inch])
        t.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))
        
        # --- Executive Summary ---
        story.append(Paragraph("2. EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        risk_level = risk_report.get("level", "Unknown")
        risk_score = risk_report.get("total_score", 0)
        risk_prob = risk_report.get("probability", None)
        mitre_list = risk_report.get("mitre_techniques", [])
        pid_probs = risk_report.get("pid_probabilities", {})
        
        level_style = self.styles['RiskLow']
        if risk_level == "High": level_style = self.styles['RiskHigh']
        elif risk_level == "Medium": level_style = self.styles['RiskMedium']
        
        story.append(Paragraph(f"Risk Level: {risk_level}", level_style))
        story.append(Paragraph(f"Total Risk Score: {risk_score}/100", self.styles['Normal']))
        if risk_prob is not None:
            story.append(Paragraph(f"Risk Probability: {int(round(risk_prob * 100))}%", self.styles['Normal']))
        story.append(Spacer(1, 10))
        if mitre_list:
            story.append(Paragraph("Mapped MITRE ATT&CK Techniques:", self.styles['Heading4']))
            story.append(Paragraph(", ".join(mitre_list), self.styles['Normal']))
            story.append(Spacer(1, 10))
        if pid_probs:
            story.append(Paragraph("Top Suspicious Processes:", self.styles['Heading4']))
            # Sort by probability desc and take top 5
            top = sorted(pid_probs.items(), key=lambda x: x[1], reverse=True)[:5]
            table_data = [["PID", "Probability"]]
            for pid, prob in top:
                table_data.append([str(pid), f"{int(round(prob*100))}%"])
            t_top = Table(table_data, colWidths=[2.0*inch, 2.0*inch])
            t_top.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ]))
            story.append(t_top)
            story.append(Spacer(1, 20))
        # --- Malware Capabilities ---
        story.append(Paragraph("3. MALWARE CAPABILITIES", self.styles['SectionHeader']))
        caps = capabilities or []
        if not caps:
            story.append(Paragraph("No explicit malware capabilities inferred.", self.styles['Normal']))
        else:
            for cap in caps[:7]:
                story.append(Paragraph(cap["name"], self.styles['Heading3']))
                story.append(Paragraph(cap["desc"], self.styles['Normal']))
                if cap.get("evidence"):
                    story.append(Paragraph("Evidence:", self.styles['Heading4']))
                    for ev in cap["evidence"][:5]:
                        story.append(Paragraph(f"• {ev}", self.styles['Normal']))
                story.append(Spacer(1, 10))
        story.append(Spacer(1, 10))
        
        if risk_report.get("details"):
            story.append(Paragraph("Key Findings:", self.styles['Heading4']))
            for detail in risk_report["details"]:
                story.append(Paragraph(f"• {detail}", self.styles['Normal']))
        else:
            story.append(Paragraph("No specific high-risk indicators were detected by the automated heuristics engine.", self.styles['Normal']))
            
        story.append(Spacer(1, 20))

        # --- Methodology ---
        story.append(Paragraph("4. RISK ASSESSMENT METHODOLOGY", self.styles['SectionHeader']))
        method_text = """
        The risk score is calculated based on a heuristic analysis of memory artifacts. 
        The system assigns weighted scores to specific anomalies found during the scan:
        """
        story.append(Paragraph(method_text, self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        scoring_data = [
            ["Anomaly Type", "Description", "Risk Weight"],
            [p_cell("Code Injection"), p_cell("Executable memory pages not backed by disk (often shellcode)"), "40 pts"],
            [p_cell("Suspicious Parent"), p_cell("Processes spawned by unexpected parents (e.g., Word spawning CMD)"), "35 pts"],
            [p_cell("Hidden Processes"), p_cell("Processes present in memory scan but unlinked from OS list (DKOM)"), "30 pts"],
            [p_cell("Masquerading"), p_cell("Process names mimicking system binaries (e.g., svhost.exe)"), "30 pts"],
            [p_cell("Encoded Command"), p_cell("Base64 or hidden commands detected in command line arguments"), "25 pts"],
            [p_cell("Unsigned Drivers"), p_cell("Kernel modules lacking valid digital signatures (Rootkits)"), "25 pts"],
            [p_cell("Suspicious Network"), p_cell("Connections to high-risk ports or known bad IPs"), "20 pts"],
            [p_cell("Suspicious Path"), p_cell("System processes running from Temp or AppData folders"), "15 pts"],
        ]
        
        # Adjusted widths to fit 10 inches (landscape)
        t_method = Table(scoring_data, colWidths=[2.0*inch, 7.0*inch, 1.0*inch])
        t_method.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.navy),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('PADDING', (0,0), (-1,-1), 2),  # Reduced padding
        ]))
        story.append(t_method)
        story.append(Spacer(1, 20))
        
        # --- Detailed Findings ---
        story.append(PageBreak())
        story.append(Paragraph("5. DETAILED FINDINGS", self.styles['SectionHeader']))
        
        if not results:
            story.append(Paragraph("No plugin results available.", self.styles['Normal']))
        
        for plugin_name, data in results.items():
            # Header
            story.append(Paragraph(f"Plugin: {plugin_name}", self.styles['Heading3']))
            
            # Description
            desc = self.plugin_descriptions.get(plugin_name, "Analysis plugin results.")
            story.append(Paragraph(f"<i>{desc}</i>", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Data Table
            if plugin_name == "internal.win.text_scan" and isinstance(data, dict):
                # Render files table (even if empty, with a helpful message)
                headers = ["Path", "File Name", "Text"]
                rows = []
                files_list = data.get("files", [])
                if files_list:
                    for row in files_list[:20]:
                        rows.append([p_cell(str(row.get("path",""))), p_cell(str(row.get("file_name",""))), p_cell(str(row.get("text","")))])
                else:
                    rows.append([p_cell("No file previews"), p_cell(""), p_cell("")])
                t_txt = Table([headers] + rows, colWidths=[4.0*inch, 2.0*inch, 4.0*inch])
                t_txt.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                    ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                ]))
                story.append(t_txt)
                story.append(Spacer(1, 10))
                # Also render summary if present
                if data.get("summary"):
                    story.append(Paragraph("Summary:", self.styles['Heading4']))
                    inner = list(data["summary"].items())
                    rows2 = [[p_cell(str(kk), self.styles['Heading4']), p_cell(str(vv))] for kk, vv in inner]
                    t_sum = Table(rows2, colWidths=[2.0*inch, 8.0*inch])
                    t_sum.setStyle(TableStyle([
                        ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ]))
                    story.append(t_sum)
                continue
            if isinstance(data, list) and len(data) > 0:
                # Get headers from first row keys if dict
                if isinstance(data[0], dict):
                    headers = list(data[0].keys())
                    # Limit columns to 5 max to fit page
                    headers = headers[:5]
                    
                    table_data = [headers]
                    # Limit rows to 20 for report readability
                    for row in data[:20]:
                        # Wrap all strings in Paragraphs to enable auto-wrapping in cells
                        row_vals = []
                        for h in headers:
                            val = str(row.get(h, ""))
                            # Always wrap text in Paragraph to prevent overlap
                            row_vals.append(p_cell(val))
                        table_data.append(row_vals)
                    
                    if len(data) > 20:
                        table_data.append([f"... ({len(data)-20} more rows) ..."] * len(headers))
                        
                    # Create table
                    # Auto-calculate widths? Hard to do perfectly.
                    # Let's just distribute evenly across 10 inches (available width)
                    col_w = 10.0 / len(headers) * inch
                    t_res = Table(table_data, colWidths=[col_w] * len(headers))
                    t_res.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                        ('FONTSIZE', (0,0), (-1,-1), 8),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ]))
                    story.append(t_res)
                else:
                    # List of strings?
                    story.append(Paragraph(str(data[:500]), self.styles['CodeBlock']))
            elif isinstance(data, dict):
                 def v_cell(value):
                     if isinstance(value, list):
                         if not value:
                             return Paragraph("[]", self.styles['TableText'])
                         if isinstance(value[0], dict):
                             headers = list(value[0].keys())[:4]
                             rows = []
                             for row in value[:10]:
                                 vals = [p_cell(str(row.get(h, ""))) for h in headers]
                                 rows.append(vals)
                             tbl = Table([headers] + rows, colWidths=[1.75*inch] * len(headers))
                             tbl.setStyle(TableStyle([
                                 ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                                 ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                                 ('VALIGN', (0,0), (-1,-1), 'TOP'),
                                 ('FONTSIZE', (0,0), (-1,-1), 8),
                             ]))
                             return tbl
                         items = [str(x) for x in value[:10]]
                         if len(value) > 10:
                             items.append(f"... ({len(value)-10} more)")
                         return Paragraph("• " + "<br/>• ".join(items), self.styles['TableText'])
                     if isinstance(value, dict):
                         inner = list(value.items())[:6]
                         rows = [[p_cell(str(kk), self.styles['Heading4']), p_cell(str(vv))] for kk, vv in inner]
                         tbl = Table(rows, colWidths=[1.5*inch, 5.5*inch])
                         tbl.setStyle(TableStyle([
                             ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                             ('VALIGN', (0,0), (-1,-1), 'TOP'),
                         ]))
                         return tbl
                     s = str(value)
                     if len(s) > 1000:
                         s = s[:1000] + " ..."
                     return Paragraph(self._inject_wrapping_space(s), self.styles['TableText'])
 
                 kv_rows = [[p_cell(str(k), self.styles['Heading4']), v_cell(v)] for k, v in data.items()]
                 t_kv = Table(kv_rows, colWidths=[3.0*inch, 7.0*inch])
                 t_kv.setStyle(TableStyle([
                     ('GRID', (0,0), (-1,-1), 0.25, colors.black),
                     ('VALIGN', (0,0), (-1,-1), 'TOP'),
                 ]))
                 story.append(t_kv)
            else:
                story.append(Paragraph("No data returned or empty result.", self.styles['Normal']))
                
            story.append(Spacer(1, 20))
            
        doc.build(story)
        return os.path.abspath(os.path.join(self.output_dir, filename))
