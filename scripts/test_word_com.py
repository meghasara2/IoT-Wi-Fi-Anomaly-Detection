try:
    import win32com.client
    word = win32com.client.Dispatch("Word.Application")
    print(f"Word COM available! Version: {word.Version}")
    word.Quit()
except Exception as e:
    print(f"Word COM error: {e}")
