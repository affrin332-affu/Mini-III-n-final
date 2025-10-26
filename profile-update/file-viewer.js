(function(){
  // Helper to get query params
  function getParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
  }

  const fileUrl = getParam('url');
  const filename = getParam('filename') || 'download';

  const titleEl = document.getElementById('file-title');
  const infoEl = document.getElementById('file-info');
  const previewEl = document.getElementById('preview');
  const downloadBtn = document.getElementById('download-btn');
  const openOriginalBtn = document.getElementById('open-original');

  if (!fileUrl) {
    titleEl.textContent = 'No file specified';
    previewEl.innerHTML = '<div class="placeholder">No file URL provided in query parameters.</div>';
    downloadBtn.disabled = true;
    openOriginalBtn.disabled = true;
    return;
  }

  titleEl.textContent = filename;
  infoEl.textContent = fileUrl;

  // A simple function to decide type by extension
  function extension(url) {
    try {
      const u = new URL(url, window.location.href);
      const parts = u.pathname.split('.');
      return parts.length > 1 ? parts.pop().toLowerCase() : '';
    } catch (e) {
      return '';
    }
  }

  const ext = extension(fileUrl);
  previewEl.innerHTML = '';

  // Image preview
  if (['png','jpg','jpeg','gif','webp','svg'].includes(ext)) {
    const img = document.createElement('img');
    img.className = 'preview-img';
    img.src = fileUrl;
    img.alt = filename;
    previewEl.appendChild(img);
  } else if (ext === 'pdf') {
    const obj = document.createElement('object');
    obj.className = 'preview-obj';
    obj.type = 'application/pdf';
    obj.data = fileUrl;
    previewEl.appendChild(obj);
  } else {
    // Generic fallback: show a link
    const div = document.createElement('div');
    div.style.textAlign = 'center';
    div.innerHTML = `<div style="margin-bottom:8px;">No inline preview available for this file type.</div><a href="${fileUrl}" target="_blank" rel="noopener">Open file in new tab</a>`;
    previewEl.appendChild(div);
  }

  // Open original file in new tab (simple)
  openOriginalBtn.addEventListener('click', () => {
    window.open(fileUrl, '_blank', 'noopener');
  });

  // Download as blob to ensure filename and force download
  downloadBtn.addEventListener('click', async () => {
    downloadBtn.disabled = true;
    downloadBtn.textContent = 'Preparing...';
    try {
      const resp = await fetch(fileUrl);
      if (!resp.ok) throw new Error('Failed to fetch file: ' + resp.status);
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      downloadBtn.textContent = 'Download';
    } catch (err) {
      console.error('Download failed:', err);
      downloadBtn.textContent = 'Download';
      alert('Download failed. See console for details.');
    } finally {
      downloadBtn.disabled = false;
    }
  });

})();
