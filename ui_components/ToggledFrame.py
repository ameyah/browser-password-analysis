import Tkinter as tk
import ttk
from ToolTip import Tooltip


class ToggledFrame(tk.Frame):
    def __init__(self, parent, text="", tooltip=None, *args, **options):
        tk.Frame.__init__(self, parent, *args, **options)

        self.show = tk.IntVar()
        self.show.set(0)

        self.title_frame = ttk.Frame(self)
        self.title_frame.pack(fill="x", expand=1)

        ttk.Label(self.title_frame, text=text).pack(side="left")

        # buttonImage = Image.open('q-mark.png')
        # help_image = tk.PhotoImage(file="q.gif")
        if tooltip is not None:
            help_button = ttk.Button(self.title_frame, text="?", width=1)
            Tooltip(help_button, text=tooltip, wraplength=250)
            help_button.pack(side="left", ipadx=0)

        self.toggle_button = ttk.Checkbutton(self.title_frame, width=2, text='+', command=self.toggle,
                                             variable=self.show, style='Toolbutton')
        self.toggle_button.pack(side="right")

        self.sub_frame = tk.Frame(self, relief="sunken", borderwidth=1)

    def toggle(self):
        if bool(self.show.get()):
            self.sub_frame.pack(fill="x", expand=1)
            self.toggle_button.configure(text='-')
        else:
            self.sub_frame.forget()
            self.toggle_button.configure(text='+')