---
description: Upload a file into OpenMind memory with memory_upload
---

When /upload is invoked, turn a file the user wants remembered into a durable OpenMind memory.

1. Take the target (a local path or an http(s) URL) from `$ARGUMENTS`. If it is empty, ask for the file and stop until the user answers.
2. Prefer a local path: the user attached or saved a file. Accept a URL only when the user explicitly gave a web link.
3. Call the OpenMind `memory_upload` tool with:
   - `target`: the path or URL to upload.
   - `ocr`: default true; pass `ocr: false` only for text files or for speed.
   - `max`: cap for OCR/downsampling (default 1400, max 4096).
4. Present what was saved: the memory id, plus a short faithful summary of the extracted content. Do not dump raw file content into the conversation.
5. Tell the user the memory is framed as untrusted data and how to remove it: `memory_forget`, `/forget`, or `memory_delete_store`.

Notes: images and PDFs are read with OCR (python3 + Pillow/tesseract, or a PDF rasterizer); other files are read as text. Only extracted text becomes a memory — raw bytes never do.
