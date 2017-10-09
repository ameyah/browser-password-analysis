from Tkinter import Tk, INSERT, Button, END, LEFT, Label, Toplevel, BOTTOM, Frame, StringVar, WORD
from ToggledFrame import ToggledFrame
import ttk
from ScrolledText import ScrolledText
from constants import *


class ToolUi():
    def __init__(self):
        self.tk = Tk()
        self.tk.geometry("500x500")
        self.text_boxes = dict()
        self.header_frame = None
        self.analysis_frame = None
        self.info_label = None
        self.info_label_text = StringVar()

    def set_window_title(self, title):
        self.tk.winfo_toplevel().title(title)

    def set_info_label_text(self, text):
        self.info_label_text.set(text)

    def render_window_frames(self):
        self.header_frame = Frame(self.tk)
        self.header_frame.pack(fill="x", pady=10)

        self.analysis_frame = Frame(self.tk)
        self.analysis_frame.pack(fill="x")

    def render_header(self, title, buttons):
        Label(self.tk, text=title, font=("Helvetica", 20)).pack()
        Label(self.tk, textvariable=self.info_label_text, fg="red", justify=LEFT).pack()
        self.render_window_frames()
        for i in xrange(len(buttons)):
            Button(self.header_frame, text=buttons[i]['title'], command=buttons[i]['callback']).pack(side=LEFT)

    @staticmethod
    def display_popup(title, message):
        dialog = Toplevel()
        dialog.title(title)
        msg = Label(dialog, text=message, justify=LEFT)
        msg.pack(padx=30, pady=30)

    def render_frames(self, frames):
        for frame in frames:
            t = ToggledFrame(self.analysis_frame, text=frame['title'], relief="raised", borderwidth=1)
            t.pack(fill="x", expand=1, pady=5, padx=2, anchor="n")
            self.text_boxes[frame['textbox_name']] = ScrolledText(t.sub_frame, wrap=WORD)
            self.text_boxes[frame['textbox_name']].tag_configure(TEXTBOX_STYLE_INFO, foreground='green')
            self.text_boxes[frame['textbox_name']].tag_configure(TEXTBOX_STYLE_HEADING, font=('Verdana', 10, 'bold'))
            self.text_boxes[frame['textbox_name']].pack()
        self.tk.mainloop()

    def text_box_insert(self, text_box, message, text_style=None):
        if not text_style:
            self.text_boxes[text_box].insert(INSERT, message)
        else:
            self.text_boxes[text_box].insert(INSERT, message, text_style)

    def clear_text_boxes(self):
        for text_box in self.text_boxes:
            self.text_boxes[text_box].delete(1.0, END)

    def preview_report(self, report_data, callback):
        dialog = Toplevel()
        dialog.title("Preview Report")
        Button(dialog, text="Send Report", command=callback).pack()
        self.text_boxes[report_data['text_box']] = ScrolledText(dialog)
        self.text_boxes[report_data['text_box']].pack()
