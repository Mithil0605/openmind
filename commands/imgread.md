---
description: Read an image or PDF into the conversation with OCR, using the OpenMind image_read tool
---

When /imgread is invoked, make an image or PDF readable by the model.

1. Take the path or URL from `$ARGUMENTS`. If it is empty, ask for it and stop
   until the user answers.
2. Call the OpenMind `image_read` tool with `target: <path-or-url>`. It returns
   the real image as an attachment plus format, dimensions and OCR text.
   - `max`: cap for the longest side before downscaling (default 1400, max 4096).
   - `ocr`: runs by default; pass `ocr: false` only for speed or when the image
     has no text.
   - `attach`: default true. Leave it on — without the attachment the model
     cannot actually see the image.
   - `pages`: for PDFs, how many pages to rasterize and OCR (default 1, max 5).
   - `attach: false` returns text and metadata only, without pixels.
3. If the tool reports that python3 is missing, or the format is unsupported,
   say so plainly and tell the user what to install (python3 with Pillow and
   tesseract, or poppler-utils/mupdf/ghostscript for PDFs). Do not claim to have
   seen an image you could not read.
4. Report what is visible: subject, embedded or OCR'd text, dimensions, and
   format. Never invent details that are not in the image.
