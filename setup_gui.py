"""Local-only credential setup. Never passes the campus password on a command line."""
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox
from campus_login import DATA_DIR, ROOT, ensure_data_dir, save_credentials


def main():
    window = tk.Tk()
    window.title('浙江大学校园网自动登录 — 本机设置')
    window.resizable(False, False)
    panel = tk.Frame(window, padx=24, pady=20)
    panel.pack()
    tk.Label(panel, text='每小时检查一次；仅在校园网未认证时登录。', anchor='w').grid(row=0, column=0, columnspan=2, sticky='w')
    tk.Label(panel, text='账号').grid(row=1, column=0, pady=(20, 8), sticky='w')
    username = tk.Entry(panel, width=34)
    username.grid(row=1, column=1, pady=(20, 8))
    tk.Label(panel, text='密码').grid(row=2, column=0, pady=8, sticky='w')
    password = tk.Entry(panel, show='*', width=34)
    password.grid(row=2, column=1, pady=8)
    text = ('密码仅在本机使用 Windows DPAPI 加密保存。\n'
            '任务在此 Windows 用户已登录时运行，锁屏不影响。\n'
            '注销 Windows 后不运行；重启后需登录此 Windows 用户。\n'
            '每小时检查意味着掉线后可能等待接近一小时才能恢复。\n'
            '源代码目录和所选 Python 解释器必须保留在原位置。\n'
            '不会主动注销校园网，不修改代理设置，不绕过验证码。\n'
            '请先阅读并同意校园网页面的文明上网承诺。')
    tk.Label(panel, text=text, justify='left', fg='#444444').grid(row=3, column=0, columnspan=2, pady=12, sticky='w')
    agreed = tk.BooleanVar(value=False)
    tk.Checkbutton(panel, text='我已阅读并同意校园网文明上网承诺', variable=agreed).grid(row=4, column=0, columnspan=2, sticky='w')
    def save():
        if not agreed.get():
            messagebox.showwarning('需确认承诺', '请先在校园网登录页面阅读文明上网承诺，并勾选确认。', parent=window)
            return
        try:
            ensure_data_dir()
            save_credentials(username.get(), password.get())
        except Exception as exc:
            # Never expose exception text: it may contain credential material.
            messagebox.showerror('凭据保存失败', '未能加密保存凭据（' + type(exc).__name__ + '）。\n'
                                 '请检查账号密码是否为空，以及本地数据目录权限。\n'
                                 '计划任务未安装。', parent=window)
            return
        password.delete(0, tk.END)
        try:
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                 str(ROOT / 'Install-Task.ps1'), '-PythonPath', sys.executable],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=40)
            if result.returncode:
                raise RuntimeError('Task installation failed')
        except Exception as exc:
            messagebox.showerror('凭据已保存，任务安装失败',
                                 '密码已在本机加密保存，但未能启用任务（' + type(exc).__name__ + '）。\n'
                                 '请在 PowerShell 中运行 Install-Task.ps1 -PythonPath '
                                 '"所用 Python 的完整路径" 查看任务权限或同名任务冲突。\n'
                                 '不要删除源代码目录或 Python 解释器。', parent=window)
            return
        messagebox.showinfo('设置完成', '密码已加密保存，每小时任务已启用。\n'
                            '登录 Windows 时也会检查。\n'
                            '当前在线时不会提交密码，因此尚未验证密码是否正确。\n'
                            '请保留源代码目录和 Python 解释器的当前位置。\n'
                            '运行日志：' + str(DATA_DIR / 'campus.log'), parent=window)
        window.destroy()
    tk.Button(panel, text='加密保存并启用每小时任务', command=save, padx=12, pady=6).grid(row=5, column=0, columnspan=2, pady=8)
    username.focus_set()
    window.mainloop()


if __name__ == '__main__':
    main()
