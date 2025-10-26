// Base URL for your backend API
const API_BASE_URL = 'http://localhost:5501/api';

// Welcome Page Elements
const welcomePage = document.getElementById('welcome-page');
const getStartedBtn = document.getElementById('get-started-btn');

// Initialize quotes rotation
function initQuotes() {
    const quotes = document.querySelectorAll('.quote-slide');
    let currentIndex = 0;
    
    // Show first quote immediately
    quotes[0].classList.add('active');
    
    // Function to show next quote
    function rotateQuotes() {
        // Prepare next quote to come in
        const nextIndex = (currentIndex + 1) % quotes.length;
        
        // Start fade out current quote
        quotes[currentIndex].style.transition = 'opacity 0.5s ease-out, transform 0.5s ease-out';
        quotes[currentIndex].classList.remove('active');
        
        // Prepare and show next quote
        setTimeout(() => {
            quotes[nextIndex].style.transition = 'opacity 0.5s ease-in, transform 0.5s ease-in';
            quotes[nextIndex].classList.add('active');
            currentIndex = nextIndex;
        }, 500);
    }
    
    // Start rotation
    setInterval(rotateQuotes, 5000);
}

// Initialize components
document.addEventListener('DOMContentLoaded', initQuotes);

// Check if user has already passed welcome page
document.addEventListener('DOMContentLoaded', () => {
    const hasPassedWelcome = sessionStorage.getItem('hasPassedWelcome');
    if (hasPassedWelcome) {
        welcomePage.classList.add('hidden');
        focusLoginContainer.classList.remove('hidden');
    }
});

// Handle Get Started button click
if (getStartedBtn) {
    getStartedBtn.addEventListener('click', () => {
        welcomePage.classList.add('hidden');
        focusLoginContainer.classList.remove('hidden');
        // Store that user has passed welcome page
        sessionStorage.setItem('hasPassedWelcome', 'true');
    });
}

// --- Global State ---
let vaultAccessKey = null; // Secret key held only upon successful unlock
let currentUserRole = 'user'; 
let storedFiles = [];
let filesToUploadQueue = []; // NEW: Holds files selected by the standard file input/dropzone before upload

// --- DOM Elements ---
const focusLoginContainer = document.getElementById('focus-login-container');
const loginWindow = document.getElementById('login-window');
const unlockButton = document.getElementById('unlock-button');
const loginFormWrapper = document.getElementById('login-form-wrapper');
const appLayout = document.getElementById('app-layout');

// Views within the Focus Window
const signinView = document.getElementById('signin-view');
const signupView = document.getElementById('signup-view');

// Messages
const signinMessage = document.getElementById('signin-message');
const signupMessage = document.getElementById('signup-message');

// Forms and Links
const signinForm = document.getElementById('signin-form');
const signupForm = document.getElementById('signup-form');

const showSignup = document.getElementById('show-signup');
const showSignin = document.getElementById('show-signin');

// Main App Elements
const addTaskForm = document.getElementById('add-task-form');
const taskBoard = document.getElementById('task-board');
const logo = document.getElementById('logo');
// Removed old vaultModal/closeVaultModal IDs
const themeToggle = document.getElementById('theme-toggle');
const menuToggle = document.getElementById('menu-toggle');
const sidebar = document.getElementById('sidebar');
const copyrightYear = document.getElementById('copyright-year');
const taskSearchInput = document.getElementById('task-search');

// Sidebar navigation links
const dashboardLink = document.getElementById('dashboard-link');
const adminPanelLink = document.getElementById('admin-panel-link');
const showAdminPanelBtn = document.getElementById('show-admin-panel');

// Main content sections
const dashboardSection = document.getElementById('dashboard');
const adminDashboardSection = document.getElementById('admin-dashboard-section');

// Admin Dashboard elements
const adminUsersList = document.getElementById('admin-users-list');
const adminAllTasksList = document.getElementById('admin-all-tasks-list');


// Task Details Modal elements
const taskDetailsModal = document.getElementById('task-details-modal');
const modalCloseBtn = taskDetailsModal.querySelector('.close-button');
const modalTaskTitle = document.getElementById('modal-task-title');
const modalTaskStatus = document.getElementById('modal-task-status');
const modalTaskPriority = document.getElementById('modal-task-priority');
const modalTaskDueDate = document.getElementById('modal-task-due-date');
const modalTaskCreatedAt = document.getElementById('modal-task-created-at');
const modalTaskDescription = document.getElementById('modal-task-description');
const saveTaskDetailsBtn = document.getElementById('save-task-details-btn');
let currentTaskToEdit = null;

// Generic Modal elements (for alerts and confirmations)
const genericModal = document.getElementById('generic-modal');
const genericModalTitle = document.getElementById('generic-modal-title');
const genericModalMessage = document.getElementById('generic-modal-message');
const genericModalActions = document.getElementById('generic-modal-actions');
const genericModalCloseBtn = document.getElementById('generic-modal-close-btn');

// NEW: User Profile DOM Elements
const userMenuButton = document.getElementById('user-menu-button');
const userDropdownMenu = document.getElementById('user-dropdown-menu');
const userEmailDisplay = document.getElementById('user-email-display');
const profileLink = document.getElementById('profile-link');
const signoutLink = document.getElementById('signout-link');
const profilePage = document.getElementById('profile-page');
const profileForm = document.getElementById('profile-form');
const profileEmailInput = document.getElementById('profile-email');
const profileMessage = document.getElementById('profile-message');
// Avatar / picture elements
const profileAvatar = document.getElementById('profile-avatar');
const profileAvatarImg = document.getElementById('profile-avatar-img');
const profilePictureInput = document.getElementById('profile-picture');

// STANDARD File Storage DOM Elements (Used for explicit file page)
const fileStorageLink = document.getElementById('file-storage-link'); 
const fileStoragePage = document.getElementById('file-storage-page'); 
const fileUploadInput = document.getElementById('file-upload-input');
const triggerUploadBtn = document.getElementById('trigger-upload-btn');
const dropZone = document.getElementById('drop-zone');
const fileListDisplay = document.getElementById('file-list');
const storedFilesList = document.getElementById('stored-files-list');

// --- NEW SECRET VAULT ELEMENTS ---
const secretVaultModal = document.getElementById('secret-vault-modal');
const closeSecretVaultBtn = document.getElementById('close-secret-vault-btn');
const vaultAccessSetupView = document.getElementById('vault-access-setup-view');
const vaultAccessUnlockView = document.getElementById('vault-access-unlock-view');
const vaultStorageView = document.getElementById('vault-storage-view');
const vaultSetupForm = document.getElementById('vault-setup-form');
const vaultUnlockForm = document.getElementById('vault-unlock-form');
const vaultAccessMessage = document.getElementById('vault-access-message'); 
const vaultUnlockMessage = document.getElementById('vault-unlock-message'); 
const securityQuestionText = document.getElementById('security-question-text');
const vaultFileInput = document.getElementById('vault-secret-file-input');
const vaultTriggerUploadBtn = document.getElementById('vault-trigger-upload-btn');
const vaultDropZone = document.getElementById('vault-drop-zone');
const vaultFileListDisplay = document.getElementById('vault-file-list');
const vaultFilesUL = document.getElementById('vault-files-ul'); 

// --- Helper Functions ---

// Displays a message on the UI (e.g., login errors, success messages)
function displayMessage(element, message, type) {
    element.textContent = message;
    element.className = `message ${type}`; 
}

// Function to decode JWT token
function decodeJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('Error decoding JWT:', error);
        return null;
    }
}

/**
 * Function to show a specific page (dashboard, admin, profile, or file-storage)
 */
function showPage(pageId, activeLinkId) {
    const pages = [dashboardSection, adminDashboardSection, profilePage, fileStoragePage];
    const links = [dashboardLink, adminPanelLink, profileLink, fileStorageLink];

    // --- NEW LOGIC TO HIDE/SHOW SEARCH INPUT ---
    const searchContainer = taskSearchInput ? taskSearchInput.closest('.search-container') : null;
    
    if (pageId === 'dashboard') {
        if (searchContainer) searchContainer.classList.remove('hidden');
    } else {
        // Hide search input for Admin Panel, Profile, and File Storage
        if (searchContainer) searchContainer.classList.add('hidden');
    }
    // -------------------------------------------

    pages.forEach(page => {
        if (page && page.id === pageId) {
            page.classList.remove('hidden');
        } else if (page) {
            page.classList.add('hidden');
        }
    });

    links.forEach(link => {
        if (link) {
            const parentLi = link.closest('li');
            if (parentLi) {
                if (link.id === activeLinkId) {
                    parentLi.classList.add('active');
                } else {
                    parentLi.classList.remove('active');
                }
            } else if (link.id === activeLinkId) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        }
    });

    if (adminPanelLink) {
        if (activeLinkId === 'admin-panel-link') {
            adminPanelLink.classList.add('active');
        } else {
            adminPanelLink.classList.remove('active');
        }
    }
}
// Controls UI visibility based on authentication state
function showLogin() {
    appLayout.classList.add('hidden');
    focusLoginContainer.classList.remove('hidden');
    loginWindow.classList.remove('success', 'expanded'); 
    loginFormWrapper.classList.add('collapsed');
    signinView.classList.remove('hidden');
    signupView.classList.add('hidden');
    // Ensure signin is visible and other auth views hidden
    displayMessage(signinMessage, '', ''); 
    displayMessage(signupMessage, '', '');
    if (adminPanelLink) adminPanelLink.classList.add('hidden');
    currentUserRole = 'user'; 
}

// Shows the main application dashboard
function showApp() {
    focusLoginContainer.classList.add('hidden');
    appLayout.classList.remove('hidden');
    loginWindow.classList.remove('success');
}

/**
 * Shows a generic modal for alerts or confirmations.
 */
function showGenericModal(title, message, buttonsConfig = [], onCloseCallback = () => {}) {
    genericModalTitle.textContent = title;
    genericModalMessage.textContent = message;
    genericModalActions.innerHTML = ''; 

    buttonsConfig.forEach(btn => {
        const button = document.createElement('button');
        button.textContent = btn.text;
        button.className = btn.className; 
        button.onclick = () => {
            hideGenericModal();
            if (btn.onClick) {
                btn.onClick();
            }
        };
        genericModalActions.appendChild(button);
    });

    genericModal.classList.remove('hidden');
    document.body.classList.add('modal-open');

    genericModal.onCloseCallback = onCloseCallback;
}

function hideGenericModal() {
    genericModal.classList.add('hidden');
    document.body.classList.remove('modal-open');
    if (genericModal.onCloseCallback) {
        genericModal.onCloseCallback();
        genericModal.onCloseCallback = null; 
    }
}

// Event listeners for generic modal close button and backdrop
if (genericModalCloseBtn) genericModalCloseBtn.addEventListener('click', hideGenericModal);
if (genericModal) {
    genericModal.addEventListener('click', (e) => {
        if (e.target === genericModal) {
            hideGenericModal();
        }
    });
}

// =========================================================================================
// === CORE FILE STORAGE FUNCTIONS (USED BY SIDEBAR LINK) ===
// =========================================================================================

/**
 * Sends a DELETE request for a specific file.
 * Added isVaultDelete flag to refresh the correct list.
 */
async function deleteStoredFile(fileId, isVaultDelete = false) {
    const token = localStorage.getItem('userToken');
    if (!token) return;

    try {
        const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            showGenericModal("Success", "File deleted successfully!", [{ text: "OK", className: "vault-btn primary" }]);
            // Refresh the appropriate list(s)
            if (isVaultDelete) {
                 fetchVaultFiles(); 
            } else {
                 fetchStoredFiles(); 
            }
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || `Deletion failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error('Error deleting file:', error);
        showGenericModal("Error", `Failed to delete file: ${error.message}`, [{ text: "OK", className: "vault-btn primary" }]);
    }
}

/**
 * Fetches the list of stored files from the backend API.
 */
async function fetchStoredFiles() {
    if (!storedFilesList) return;
    const token = localStorage.getItem('userToken');
    if (!token) {
        storedFilesList.innerHTML = '<li class="placeholder-text">Please sign in to view files.</li>';
        return;
    }

    storedFilesList.innerHTML = '<li class="placeholder-text">Loading stored files...</li>';

    try {
        const response = await fetch(`${API_BASE_URL}/files`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` } 
        });

        if (response.ok) {
            const files = await response.json();
            storedFiles = files; 
            renderStoredFiles(files);
        } else {
            throw new Error(`Failed to fetch files. Status: ${response.status}`);
        }
    } catch (error) {
        console.error('Error fetching stored files:', error);
        storedFilesList.innerHTML = '<li class="placeholder-text error">Failed to load files. Check console for API errors.</li>';
    }
}

/**
 * Renders the "Your Stored Files" list.
 */
function renderStoredFiles(files) {
    if (!storedFilesList) return;

    storedFilesList.innerHTML = ''; 

    if (files.length === 0) {
        storedFilesList.innerHTML = '<li class="placeholder-text">No files currently stored.</li>';
        return;
    }

    files.forEach(file => {
        const filename = file.name;
        
        const li = document.createElement('li');
        li.style.borderBottom = '1px solid var(--border-color)';
        li.style.padding = '0.5rem 0';
        li.style.display = 'flex';
        li.style.justifyContent = 'space-between';
        li.style.alignItems = 'center';
        
        const fileSize = file.size ? (file.size / 1024).toFixed(2) : 'N/A';
        const uploadDate = file.uploadDate ? new Date(file.uploadDate).toLocaleDateString() : 'N/A';
        
        li.innerHTML = `
            <div>
                <strong>${filename}</strong> 
                <span style="font-size:0.8em; opacity:0.7;">(Uploaded: ${uploadDate} - ${fileSize} KB)</span>
            </div>
            <div style="display:flex; gap:6px; align-items:center;">
                <button class="download-file-btn vault-btn neutral" data-file-id="${file._id}" data-filename="${filename}" style="padding: 0.2rem 0.5rem;">Download</button>
                <button class="delete-file-btn vault-btn secondary" data-file-id="${file._id}" style="padding: 0.2rem 0.5rem; background: var(--high-priority-color); color: white;">Delete</button>
            </div>
        `;
        storedFilesList.appendChild(li);
    });

    // Attach click handlers for download and delete
    storedFilesList.querySelectorAll('.download-file-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const fileId = e.target.dataset.fileId;
            const filename = e.target.dataset.filename || 'download';
            downloadStoredFile(fileId, filename);
        });
    });

    storedFilesList.querySelectorAll('.delete-file-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const fileIdToDelete = e.target.dataset.fileId;
            deleteStoredFile(fileIdToDelete, false); // Standard file delete
        });
    });
}


/**
 * Triggers download of a stored (non-encrypted) file.
 * It uses the file metadata returned by the server (the `url` property) to
 * create a temporary anchor and click it so the browser downloads the file.
 */
function downloadStoredFile(fileId, filename) {
    const fileRecord = storedFiles.find(f => f._id === fileId);
    if (!fileRecord || !fileRecord.url) {
        showGenericModal('Download Error', 'File metadata or URL is missing. Try refreshing the file list.', [{ text: 'OK', className: 'vault-btn primary' }]);
        return;
    }

    try {
        // Open the file in a separate viewer page so the user can preview and explicitly download.
        // We encode the URL and filename as query params.
        const viewerUrl = `./file-viewer.html?url=${encodeURIComponent(fileRecord.url)}&filename=${encodeURIComponent(filename || fileRecord.name || 'download')}`;
        window.open(viewerUrl, '_blank');
    } catch (error) {
        console.error('Download stored file failed:', error);
        showGenericModal('Download Failed', `Could not download ${filename}.`, [{ text: 'OK', className: 'vault-btn primary' }]);
    }
}


/**
 * Sends files to the backend server using FormData.
 */
async function uploadFiles(filesToUpload) {
    if (!triggerUploadBtn || filesToUpload.length === 0) return;
    const token = localStorage.getItem('userToken');
    if (!token) {
        showGenericModal("Authentication Error", "Please sign in to upload files.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }

    // 1. Show Loading State
    const originalText = triggerUploadBtn.textContent;
    triggerUploadBtn.textContent = 'Uploading... Please wait.';
    triggerUploadBtn.disabled = true;

    const formData = new FormData();
    filesToUpload.forEach(file => {
        formData.append('files', file); 
    });

    try {
        const response = await fetch(`${API_BASE_URL}/files/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            // The browser automatically sets the correct 'Content-Type: multipart/form-data' header boundary for FormData
            body: formData
        });

        if (response.ok) {
            await fetchStoredFiles(); 

            fileListDisplay.innerHTML = `<p style="color: var(--low-priority-color); font-weight: bold; margin: 0;">Upload Success! ${filesToUpload.length} file(s) saved.</p>`;
            
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || `Upload failed with status: ${response.status}`);
        }

    } catch (error) {
        console.error('File upload error:', error);
        fileListDisplay.innerHTML = `<p class="message error">Upload Failed: ${error.message}</p>`;
    } finally {
        triggerUploadBtn.textContent = originalText;
        triggerUploadBtn.disabled = true; // Disable until new files are selected
        filesToUploadQueue = []; // Clear the queue
        if (fileUploadInput) fileUploadInput.value = null; 
    }
}
/**
 * Generic handler to visually update the UI with selected files
 * and stage them for upload (Standard Files).
 */
/**
 * Generic handler to visually update the UI with selected files
 * and stage them for upload (Standard Files).
 */
function handleFiles(files) {
    const fileArray = Array.from(files);
    if (!triggerUploadBtn || fileArray.length === 0) return;

    // 1. Store the files in the global queue
    filesToUploadQueue = fileArray;

    // 2. Display selected files and enable the upload button
    if (fileListDisplay) {
        fileListDisplay.innerHTML = '';
        const ul = document.createElement('ul');
        fileArray.forEach(file => {
            const li = document.createElement('li');
            li.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
            ul.appendChild(li);
        });
        fileListDisplay.appendChild(ul);
        fileListDisplay.innerHTML += `<p style="color: var(--low-priority-color); font-weight: bold; margin-top: 5px;">${fileArray.length} file(s) ready to upload.</p>`;
    }

    triggerUploadBtn.textContent = `Upload ${fileArray.length} File(s)`;
    triggerUploadBtn.disabled = false;
}

/**
 * Sends files to the backend server using FormData.
 */
async function uploadFiles(filesToUpload) {
    if (filesToUpload.length === 0) return;
    const token = localStorage.getItem('userToken');
    if (!token) {
        showGenericModal("Authentication Error", "Please sign in to upload files.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }

    // 1. Show Loading State
    const originalText = triggerUploadBtn.textContent;
    triggerUploadBtn.textContent = 'Uploading... Please wait.';
    triggerUploadBtn.disabled = true;

    const formData = new FormData();
    filesToUpload.forEach(file => {
        formData.append('files', file); 
    });

    try {
        const response = await fetch(`${API_BASE_URL}/files/upload`, {
            method: 'POST',
            // Crucial: Send the token for authentication
            headers: {
                'Authorization': `Bearer ${token}`
            },
            // The browser correctly sets Content-Type for FormData
            body: formData
        });

        if (response.ok) {
            await fetchStoredFiles(); 
            filesToUploadQueue = []; // Clear queue on success

            fileListDisplay.innerHTML = `<p style="color: var(--low-priority-color); font-weight: bold; margin: 0;">Upload Success! ${filesToUpload.length} file(s) saved.</p>`;
            
        } else {
            // Log full error status for debugging
            const errorData = await response.json().catch(() => ({ error: 'Unknown server error (non-JSON response).' }));
            console.error('File upload failed. Status:', response.status, 'Error:', errorData);
            throw new Error(errorData.error || `Upload failed with status: ${response.status}`);
        }

    } catch (error) {
        console.error('File upload error (Client-side Catch):', error);
        fileListDisplay.innerHTML = `<p class="message error">Upload Failed: ${error.message}</p>`;
    } finally {
        triggerUploadBtn.textContent = originalText;
        triggerUploadBtn.disabled = true; 
        if (fileUploadInput) fileUploadInput.value = null; 
    }
}
// =========================================================================================
// === CORE SECRET VAULT FILE FUNCTIONS (Requires CryptoJS) ===
// =========================================================================================

/**
 * Uploads, Encrypts, and sends files to the backend for storage.
 * NOTE: Requires CryptoJS library to be loaded in the HTML.
 */
async function uploadSecretFiles(filesToUpload) {
    if (!vaultTriggerUploadBtn || filesToUpload.length === 0 || !vaultAccessKey) {
        showGenericModal("Vault Error", "Vault is locked or no files selected.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }
    // Check if CryptoJS is available
    if (typeof CryptoJS === 'undefined') {
        return showGenericModal("Error", "Encryption library (CryptoJS) is missing. Cannot upload secret files.", [{ text: "OK", className: "vault-btn primary" }]);
    }

    const token = localStorage.getItem('userToken');
    if (!token) return showLogin();

    const originalText = vaultTriggerUploadBtn.textContent;
    vaultTriggerUploadBtn.textContent = 'Encrypting & Uploading...';
    vaultTriggerUploadBtn.disabled = true;

    // Use a single FormData object for all files
    const formData = new FormData();
    const uploadPromises = Array.from(filesToUpload).map(file => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    // 1. ENCRYPT the file content (the ArrayBuffer)
                    const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
                    const encrypted = CryptoJS.AES.encrypt(wordArray, vaultAccessKey).toString();
                    
                    // 2. Wrap encrypted data in a Blob
                    const encryptedBlob = new Blob([encrypted], { type: 'text/plain' });
                    
                    // 3. Append to FormData with the original file name
                    formData.append('files', encryptedBlob, file.name);
                    resolve();
                } catch (error) {
                    reject(new Error(`Encryption failed for ${file.name}: ${error.message}`));
                }
            };
            reader.onerror = (error) => reject(new Error(`File read failed for ${file.name}: ${error.message}`));
            reader.readAsArrayBuffer(file);
        });
    });

    try {
        await Promise.all(uploadPromises);

        // 4. Send the encrypted files to the standard file upload API endpoint
        const response = await fetch(`${API_BASE_URL}/files/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });

        if (response.ok) {
            await fetchVaultFiles(); // Refresh the vault file list
            if (vaultFileListDisplay) vaultFileListDisplay.innerHTML = `<p style="color: var(--low-priority-color); font-weight: bold; margin: 0;">Upload Success! ${filesToUpload.length} file(s) encrypted and saved.</p>`;
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || `Upload failed with status: ${response.status}`);
        }

    } catch (error) {
        console.error('Secret file upload error:', error);
        if (vaultFileListDisplay) vaultFileListDisplay.innerHTML = `<p class="message error">Upload Failed: ${error.message}</p>`;
    } finally {
        vaultTriggerUploadBtn.textContent = originalText;
        vaultTriggerUploadBtn.disabled = false;
        if (vaultFileInput) vaultFileInput.value = null;
    }
}

/**
 * Fetches, decrypts, and downloads a specific file.
 */
async function downloadSecretFile(fileId, filename) {
    if (!vaultAccessKey) {
        return showGenericModal("Vault Locked", "Please unlock the vault to download and decrypt files.", [{ text: "OK", className: "vault-btn primary" }]);
    }
    const token = localStorage.getItem('userToken');
    if (!token) return showLogin();

    try {
        // 1. Find the file record to get the URL
        const fileRecord = storedFiles.find(f => f._id === fileId);
        if (!fileRecord || !fileRecord.url) throw new Error('File metadata or URL missing.');

        // 2. Fetch the file content from the server (which is the encrypted text)
        const response = await fetch(fileRecord.url); 
        if (!response.ok) throw new Error(`Failed to fetch encrypted file. Status: ${response.status}`);
        
        // 3. Read the encrypted content as plain text
        const encryptedText = await response.text();

        // 4. DECRYPT the file content
        const decrypted = CryptoJS.AES.decrypt(encryptedText, vaultAccessKey);
        const typedArray = convertWordArrayToUint8Array(decrypted);

        // 5. Create a Blob and trigger download
        const blob = new Blob([typedArray]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename; // Use original filename
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);

    } catch (error) {
        console.error('Secret file download/decryption error:', error);
        showGenericModal("Decryption Failed", `Could not decrypt or download ${filename}. The vault key might be incorrect, or the file is corrupted.`, [{ text: "OK", className: "vault-btn primary" }]);
    }
}

/**
 * Helper to convert CryptoJS WordArray to Uint8Array for Blob creation.
 */
function convertWordArrayToUint8Array(wordArray) {

    // Helper to convert CryptoJS WordArray to Uint8Array for Blob creation.
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    let i = 0;
    let j = 0;
    while(true) {
        if(i >= l)
            break;
        const w = words[j++];
        result[i++] = w & 0xff;
        if(i >= l)
            break;
        result[i++] = (w >>> 8) & 0xff;
        if(i >= l)
            break;
        result[i++] = (w >>> 16) & 0xff;
        if(i >= l)
            break;
        result[i++] = (w >>> 24) & 0xff;
    }
    return result;
}

// Small helper to hash strings (used for private vault). Uses subtle.crypto if available, falls back to btoa.
async function hashString(input) {
    try {
        if (window.crypto && window.crypto.subtle) {
            const enc = new TextEncoder();
            const data = enc.encode(input);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            // Fallback: base64 of input (not cryptographically secure) - acceptable for local demo
            return btoa(input);
        }
    } catch (e) {
        console.warn('hashString failed, using fallback:', e);
        return btoa(input);
    }
}

/**
 * Renders the file list inside the vault modal.
 * Reuses the existing storedFiles array.
 */
function renderVaultFiles(files) {
    if (!vaultFilesUL) return;

    vaultFilesUL.innerHTML = ''; 

    if (files.length === 0) {
        vaultFilesUL.innerHTML = '<li class="placeholder-text">No secret files currently stored.</li>';
        return;
    }

    files.forEach(file => {
        const li = document.createElement('li');
        li.style.borderBottom = '1px solid var(--border-color)';
        li.style.padding = '0.5rem 0';
        li.style.display = 'flex';
        li.style.justifyContent = 'space-between';
        li.style.alignItems = 'center';

        const fileSize = file.size ? (file.size / 1024).toFixed(2) : 'N/A';
        const uploadDate = file.uploadDate ? new Date(file.uploadDate).toLocaleDateString() : 'N/A';

        li.innerHTML = `
            <div style="flex-grow: 1;">
                <strong>${file.name}</strong>
                <span style="font-size:0.8em; opacity:0.7;">(Encrypted - ${fileSize} KB)</span>
            </div>
            <button class="download-secret-btn vault-btn secondary" data-file-id="${file._id}" data-filename="${file.name}" style="padding: 0.2rem 0.5rem; margin-right: 5px;">Download</button>
            <button class="delete-file-btn vault-btn secondary" data-file-id="${file._id}" style="padding: 0.2rem 0.5rem; background: var(--high-priority-color); color: white;">Delete</button>
        `;
        vaultFilesUL.appendChild(li);
    });

    vaultFilesUL.querySelectorAll('.download-secret-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            downloadSecretFile(e.target.dataset.fileId, e.target.dataset.filename);
        });
    });
    
    // Use the existing generic deleteStoredFile function (with vault flag)
    vaultFilesUL.querySelectorAll('.delete-file-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const fileIdToDelete = e.target.dataset.fileId;
            deleteStoredFile(fileIdToDelete, true); // Pass true to refresh vault view on success
        });
    });
}

/**
 * Shows the vault storage view after successful setup/unlock.
 * Also fetches the file list.
 */
function showVaultStorage() {
    if(vaultAccessSetupView) vaultAccessSetupView.classList.add('hidden');
    if(vaultAccessUnlockView) vaultAccessUnlockView.classList.add('hidden');
    if(vaultStorageView) vaultStorageView.classList.remove('hidden');
    
    fetchVaultFiles(); // Load the encrypted file list
}

/**
 * Fetches the list of stored files and renders them in the vault view.
 */
async function fetchVaultFiles() {
    // Reuses the general file list logic but renders to the vault's UL
    await fetchStoredFiles(); 
    renderVaultFiles(storedFiles);
}

// --- NEW VAULT SETUP AND UNLOCK LOGIC ---

/**
 * Handles the submission of the vault setup form.
 * Assumes fields: vault-key-new (for vaultKey) and vault-security-q (for securityQuestion).
 */
async function setupVault(e) {
    e.preventDefault();
    const token = localStorage.getItem('userToken');
    if (!token) return showLogin();

    const vaultKey = document.getElementById('vault-key-new').value;
    const securityQuestion = document.getElementById('vault-security-q').value;

    if (!vaultKey || !securityQuestion) {
        displayMessage(vaultAccessMessage, 'Key and Security Question cannot be empty.', 'error');
        return;
    }

    displayMessage(vaultAccessMessage, 'Setting up vault...', '');

    try {
        const response = await fetch(`${API_BASE_URL}/vault/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ vaultKey, securityQuestion })
        });

        const data = await response.json();

        if (response.ok) {
            // CRITICAL: Set the client-side key for the session
            vaultAccessKey = vaultKey;
            displayMessage(vaultAccessMessage, data.message || 'Vault setup complete! Unlocked for this session.', 'success');
            showVaultStorage();
        } else {
            displayMessage(vaultAccessMessage, data.error || 'Vault setup failed.', 'error');
        }
    } catch (error) {
        console.error('Vault setup error:', error);
        displayMessage(vaultAccessMessage, 'An API error occurred during setup.', 'error');
    }
}
// Function to check vault status (must be in global scope)
async function checkVaultAccessStatus() {
    const token = localStorage.getItem('userToken');
    if (!secretVaultModal || !token) {
        showLogin(); 
        return;
    }
    
    // Clear any existing key and show the modal
    vaultAccessKey = null; 
    secretVaultModal.classList.remove('hidden');

    try {
        // This is the fetch call that results in the 404 if the backend route is missing
        const response = await fetch(`${API_BASE_URL}/vault/status`, { 
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` } 
        });
        const data = await response.json();

        // Clear previous messages
        if (vaultAccessMessage) vaultAccessMessage.textContent = '';
        if (vaultUnlockMessage) vaultUnlockMessage.textContent = '';

        if (data.isSetup) {
            // Vault is set up, show the unlock view
            if(vaultAccessSetupView) vaultAccessSetupView.classList.add('hidden');
            if(vaultAccessUnlockView) vaultAccessUnlockView.classList.remove('hidden');
            if(vaultStorageView) vaultStorageView.classList.add('hidden');
            if (securityQuestionText) securityQuestionText.textContent = data.securityQuestion;
        } else {
            // Vault is not set up, show the setup view
            if(vaultAccessSetupView) vaultAccessSetupView.classList.remove('hidden');
            if(vaultAccessUnlockView) vaultAccessUnlockView.classList.add('hidden');
            if(vaultStorageView) vaultStorageView.classList.add('hidden');
        }
    } catch (error) {
        if (vaultAccessMessage) {
            vaultAccessMessage.textContent = 'API Error: Cannot check vault status.';
            vaultAccessMessage.className = 'message error';
        }
        console.error('Vault status check failed:', error);
    }
}
/**
 * Handles the submission of the vault unlock form.
 * Assumes field: vault-key-unlock (for the key).
 */
async function unlockVault(e) {
    e.preventDefault();
    const token = localStorage.getItem('userToken');
    if (!token) return showLogin();

    const vaultKey = document.getElementById('vault-key-unlock').value;

    displayMessage(vaultUnlockMessage, 'Verifying key...', '');

    try {
        const response = await fetch(`${API_BASE_URL}/vault/unlock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ vaultKey })
        });

        const data = await response.json();

        if (response.ok) {
            // CRITICAL: Set the client-side key for the session
            vaultAccessKey = vaultKey;
            displayMessage(vaultUnlockMessage, 'Vault unlocked successfully! Access granted.', 'success');
            showVaultStorage();
        } else {
            vaultAccessKey = null; // Clear key on failure
            displayMessage(vaultUnlockMessage, data.error || 'Unlock failed. Invalid key.', 'error');
        }
    } catch (error) {
        console.error('Vault unlock error:', error);
        vaultAccessKey = null;
        displayMessage(vaultUnlockMessage, 'An API error occurred during unlock.', 'error');
    }
}

// -------------------------------------------------------------


// --- 2. AUTHENTICATION LOGIC (MongoDB Backend) ---

// Checks if a user token exists in localStorage to determine login state
async function checkAuthStatus() {
    const token = localStorage.getItem('userToken');
    if (token) {
        const decodedToken = decodeJwt(token);
        if (decodedToken && decodedToken.role) {
            currentUserRole = decodedToken.role;
            if (currentUserRole === 'admin') {
                if (adminPanelLink) adminPanelLink.classList.remove('hidden');
            } else {
                if (adminPanelLink) adminPanelLink.classList.add('hidden');
            }
        }
        showApp();
        showPage('dashboard', 'dashboard-link'); 
        fetchTasks(); 
    } else {
        showLogin();
    }
}

// Handles user sign-up - No automatic login
if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        displayMessage(signupMessage, 'Registering...', '');
        const email = document.getElementById('signup-email').value;
        const password = document.getElementById('signup-password').value;

        try {
            const response = await fetch(`${API_BASE_URL}/auth/signup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok) {
                displayMessage(signupMessage, data.message || 'Account created successfully! Please sign in.', 'success');
                signupView.classList.add('hidden');
                signinView.classList.remove('hidden');
                document.getElementById('signup-email').value = '';
                document.getElementById('signup-password').value = '';
            } else {
                displayMessage(signupMessage, data.error || 'Signup failed.', 'error');
            }
        } catch (error) {
            console.error('Signup fetch error:', error);
            displayMessage(signupMessage, 'An error occurred during signup. Please try again.', 'error');
        }
    });
}

// Handles user sign-in
if (signinForm) {
    signinForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        displayMessage(signinMessage, 'Verifying...', '');
        const email = document.getElementById('signin-email').value;
        const password = document.getElementById('signin-password').value;

        try {
            const response = await fetch(`${API_BASE_URL}/auth/signin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('userToken', data.token); 
                const decodedToken = decodeJwt(data.token);
                if (decodedToken && decodedToken.role) {
                    currentUserRole = decodedToken.role;
                    if (currentUserRole === 'admin') {
                        if (adminPanelLink) adminPanelLink.classList.remove('hidden');
                    } else {
                        if (adminPanelLink) adminPanelLink.classList.add('hidden');
                    }
                }

                loginWindow.classList.add('success'); 
                setTimeout(() => {
                    showApp();
                    showPage('dashboard', 'dashboard-link');
                    fetchTasks(); 
                }, 600);
            } else {
                displayMessage(signinMessage, data.error || 'Login failed. Check your credentials.', 'error');
            }
        } catch (error) {
            console.error('Signin fetch error:', error);
            displayMessage(signinMessage, 'An error occurred during login. Please try again.', 'error');
        }
    });
}

// Forgot password functionality removed

// --- Auth View Toggling ---
if (showSignup) showSignup.addEventListener('click', (e) => {
    e.preventDefault();
    displayMessage(signupMessage, '', ''); 
    signinView.classList.add('hidden');
    signupView.classList.remove('hidden');
});

if (showSignin) showSignin.addEventListener('click', (e) => {
    e.preventDefault();
    displayMessage(signinMessage, '', ''); 
    signupView.classList.add('hidden');
    signinView.classList.remove('hidden');
});
// Note: forgot-password links and handlers removed


// --- 3. TASK MANAGEMENT (MongoDB Backend) ---

// Fetches tasks from the backend for the current user
const fetchTasks = async () => {
    const token = localStorage.getItem('userToken');
    if (!token) {
        console.warn('No token found, cannot fetch tasks.');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/tasks`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` } 
        });

        if (!response.ok) {
            if (response.status === 401) {
                localStorage.removeItem('userToken');
                showLogin();
                displayMessage(signinMessage, 'Session expired. Please sign in again.', 'error');
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const tasks = await response.json();
        renderTasks(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
    }
};

// Renders tasks onto the Kanban board columns
const renderTasks = (tasks) => {
    const todoColumn = document.getElementById('To Do');
    const inProgressColumn = document.getElementById('In Progress');
    const doneColumn = document.getElementById('Done');

    if (todoColumn) todoColumn.innerHTML = '<h2>To Do</h2>';
    if (inProgressColumn) inProgressColumn.innerHTML = '<h2>In Progress</h2>';
    if (doneColumn) doneColumn.innerHTML = '<h2>Done</h2>';

    tasks.forEach(task => {
        const column = document.getElementById(task.status);
        if (column) {
            const card = document.createElement('div');
            card.className = `task-card priority-${task.priority.toLowerCase()}`;
            card.id = `task-${task._id}`; 
            card.draggable = true;
            card.dataset.id = task._id; 

            const dueDate = task.due_date ? new Date(task.due_date).toLocaleDateString() : 'No Due Date';

            card.innerHTML = `
                <h3>${task.title}</h3>
                <p class="task-priority">${task.priority} Priority</p>
                <p class="task-due-date">Due: ${dueDate}</p>
                <div class="task-actions">
                    <button class="delete-task-btn" data-task-id="${task._id}" title="Delete Task">×</button>
                </div>
            `;
            card.addEventListener('dragstart', dragStart);
            // Ensure dragging class is removed after drag finishes
            card.addEventListener('dragend', (e) => {
                try { e.currentTarget.classList.remove('dragging'); } catch (err) { /* ignore */ }
            });
            card.addEventListener('click', (e) => {
                if (!e.target.closest('.delete-task-btn')) {
                    showTaskDetailsModal(task);
                }
            });
            column.appendChild(card);
        }
    });
};

// Adds a new task
if (addTaskForm) {
    addTaskForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const titleInput = document.getElementById('task-title');
        const priorityInput = document.getElementById('task-priority');
        const dueDateInput = document.getElementById('task-due-date'); 

        const title = titleInput.value.trim();
        const priority = priorityInput.value;
        const due_date = dueDateInput.value || null; 
        const token = localStorage.getItem('userToken');

        if (title && token) {
            try {
                const response = await fetch(`${API_BASE_URL}/tasks`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ title, priority, due_date, status: 'To Do' })
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                titleInput.value = '';
                priorityInput.value = 'Medium'; 
                dueDateInput.value = ''; 
                fetchTasks();
            } catch (error) {
                console.error('Error adding task:', error);
                showGenericModal(
                    "Error",
                    "Failed to add task. Please try again.",
                    [{ text: "OK", className: "vault-btn primary" }]
                );
            }
        }
    });
}

// Handles task deletion via event delegation
if (taskBoard) {
    taskBoard.addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-task-btn')) {
            const taskId = e.target.getAttribute('data-task-id');
            
            showGenericModal(
                "Confirm Deletion",
                "Are you sure you want to delete this task?",
                [
                    { text: "Delete", className: "vault-btn primary", onClick: async () => {
                        // Optimistic UI: remove the card immediately
                        try {
                            const card = document.getElementById(`task-${taskId}`);
                            if (card && card.parentNode) card.parentNode.removeChild(card);
                        } catch (err) {
                            console.warn('Could not remove card element optimistically:', err);
                        }

                        // Attempt server delete but do not block the UI on failure
                        try {
                            const token = localStorage.getItem('userToken');
                            if (!token) {
                                console.warn('Delete: no user token found; deletion will be local only.');
                                return;
                            }

                            const response = await fetch(`${API_BASE_URL}/tasks/${taskId}`, {
                                method: 'DELETE',
                                headers: { 'Authorization': `Bearer ${token}` }
                            });

                            if (!response.ok) {
                                let errText = `HTTP ${response.status}`;
                                try {
                                    const errData = await response.json();
                                    if (errData && (errData.error || errData.message)) errText += `: ${errData.error || errData.message}`;
                                } catch (parseErr) {
                                    console.warn('Delete: failed to parse server error JSON', parseErr);
                                }
                                console.warn('Server rejected delete request for task', taskId, errText);
                                // Keep UI removed (optimistic); do not show blocking modal
                            }
                        } catch (error) {
                            console.warn('Network error during task delete (optimistic UI kept):', error);
                        }
                    }},
                    { text: "Cancel", className: "vault-btn secondary" }
                ]
            );
        }
    });
}

// --- Search and Filter Logic ---
const priorityFilter = document.getElementById('task-filter-priority');

if (taskSearchInput) taskSearchInput.addEventListener('input', filterTasks);
if (priorityFilter) priorityFilter.addEventListener('change', filterTasks);

function filterTasks() {
    const searchTerm = taskSearchInput.value.toLowerCase();
    const selectedPriority = priorityFilter ? priorityFilter.value : 'All';
    const tasks = document.querySelectorAll('.task-card');

    tasks.forEach(task => {
        const title = task.querySelector('h3') ? task.querySelector('h3').textContent.toLowerCase() : '';
        const priorityTextEl = task.querySelector('.task-priority');
        const priorityText = priorityTextEl ? priorityTextEl.textContent.replace(' Priority','').trim() : '';

        const matchesText = title.includes(searchTerm);
        const matchesPriority = (selectedPriority === 'All') || (priorityText === selectedPriority);

        if (matchesText && matchesPriority) {
            task.style.display = 'block';
        } else {
            task.style.display = 'none';
        }
    });
}

// --- 4. DRAG-AND-DROP LOGIC ---
function dragStart(e) {
    // Use currentTarget to ensure we always use the card element's id
    const element = e.currentTarget || e.target;
    const id = element && element.id ? element.id : '';
    // Defensive logging to help debug drag/drop issues
    // (kept minimal so it can be left in for troubleshooting)
    // console.debug('dragStart:', { id, elementTag: element && element.tagName });
    try {
        if (e.dataTransfer) {
            e.dataTransfer.setData('text/plain', id);
            e.dataTransfer.effectAllowed = 'move';
        }
    } catch (err) {
        console.warn('dragStart dataTransfer set failed:', err);
    }
    // Minimal debug log for troubleshooting drag events
    console.debug && console.debug('dragStart -> id:', id);
    if (element && element.classList) element.classList.add('dragging');
}

// Global drop function for drag-and-drop
window.drop = async (e) => {
    e.preventDefault();
    const taskId = e.dataTransfer.getData('text/plain');
    // Defensive: if taskId empty, try to find closest dragged element
    if (!taskId) {
        const dragging = document.querySelector('.task-card.dragging');
        if (dragging) taskId = dragging.id;
    }
    const draggedElement = document.getElementById(taskId);
    const targetColumn = e.target.closest('.task-column'); 
    document.querySelectorAll('.task-card').forEach(card => card.classList.remove('dragging')); 

    if (draggedElement && targetColumn) {
        const newStatus = targetColumn.id; 

        console.debug && console.debug('drop -> taskId:', taskId, 'newStatus:', newStatus);

        // Append the dragged card to the new column
        targetColumn.appendChild(draggedElement);

        // Update task status in the backend
        const token = localStorage.getItem('userToken');
        // If no token, allow the UI move to remain (optimistic) and skip server update
        if (!token) {
            console.warn('drop: no userToken found in localStorage. UI updated optimistically; server update skipped.');
            return;
        }

        const idToUpdate = draggedElement.dataset.id;
        if (!idToUpdate) {
            console.warn('drop: dragged element has no data-id attribute:', draggedElement);
            // Cannot PATCH without id; keep UI change and bail silently
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/tasks/${idToUpdate}`, { 
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ status: newStatus })
            });

            if (!response.ok) {
                // Non-blocking: log server error but keep optimistic UI change
                let errText = `HTTP ${response.status}`;
                try {
                    const errData = await response.json();
                    if (errData && (errData.error || errData.message)) {
                        errText += `: ${errData.error || errData.message}`;
                    }
                } catch (parseErr) {
                    console.warn('drop: failed to parse error JSON from server', parseErr);
                }
                console.warn('drop: server rejected status update for task', idToUpdate, errText);
                return; // leave UI as-is (optimistic)
            }
        } catch (error) {
            console.warn('drop: network error while updating task status (optimistic UI retained):', error);
            return; // leave UI as-is
        }
    }
};

// --- 5. UI & SECRET VAULT LOGIC ---
if (themeToggle) themeToggle.addEventListener('click', () => document.body.classList.toggle('dark-mode'));

let clickCount = 0;
// =======================================================
// === MODIFIED LOGO CLICK: TRIGGER SECRET VAULT MODAL ===
// =======================================================
if (logo) {
    logo.addEventListener('click', () => {
        clickCount++;
        setTimeout(() => { clickCount = 0; }, 600); 
        if (clickCount === 3) {
            clickCount = 0;
            const token = localStorage.getItem('userToken');
            if (secretVaultModal && token) {
                checkVaultAccessStatus(); // Start the Vault flow
            } else {
                showGenericModal("Access Denied", "Please sign in to access the Secret Vault.", [{ text: "OK", className: "vault-btn primary" }]);
            }
        }
    });
}

if (closeSecretVaultBtn) {
    closeSecretVaultBtn.addEventListener('click', () => {
        if (secretVaultModal) secretVaultModal.classList.add('hidden');
    });
}
// Removed closeVaultModal logic as the ID is no longer used.

// --- 6. Menu Toggle Logic ---
if (menuToggle) {
    menuToggle.addEventListener('click', () => {
        if (sidebar) sidebar.classList.toggle('collapsed');
    });
}

// --- Task Details Modal Logic ---
function showTaskDetailsModal(task) {
    currentTaskToEdit = task; 
    if (modalTaskTitle) modalTaskTitle.textContent = task.title;
    if (modalTaskStatus) modalTaskStatus.textContent = task.status;
    if (modalTaskPriority) modalTaskPriority.textContent = task.priority;
    if (modalTaskDueDate) modalTaskDueDate.textContent = task.due_date ? new Date(task.due_date).toLocaleDateString() : 'N/A';
    if (modalTaskCreatedAt) modalTaskCreatedAt.textContent = new Date(task.created_at).toLocaleString();
    if (modalTaskDescription) modalTaskDescription.value = task.description || ''; 

    if (taskDetailsModal) taskDetailsModal.classList.remove('hidden');
    document.body.classList.add('modal-open'); 
}

function hideTaskDetailsModal() {
    if (taskDetailsModal) taskDetailsModal.classList.add('hidden');
    document.body.classList.remove('modal-open');
    currentTaskToEdit = null; 
}

// Event listeners for task details modal
if (modalCloseBtn) modalCloseBtn.addEventListener('click', hideTaskDetailsModal);
if (taskDetailsModal) {
    taskDetailsModal.addEventListener('click', (e) => {
        if (e.target === taskDetailsModal) {
            hideTaskDetailsModal();
        }
    });
}

// Save updated task details (e.g., description)
if (saveTaskDetailsBtn) {
    saveTaskDetailsBtn.addEventListener('click', async () => {
        if (!currentTaskToEdit) return;

        const newDescription = modalTaskDescription.value;
        const token = localStorage.getItem('userToken');

        // Optimistic: update UI and close modal immediately
        try {
            currentTaskToEdit.description = newDescription; 
            hideTaskDetailsModal();
            // Update the task card UI description if present (non-blocking)
            const card = document.getElementById(`task-${currentTaskToEdit._id}`);
            if (card) {
                const descEl = card.querySelector('.task-description');
                if (descEl) descEl.textContent = newDescription;
            }
        } catch (uiErr) {
            console.warn('Could not apply optimistic UI update for task description:', uiErr);
        }

        // Attempt to persist the change to server in background; log on failure
        (async () => {
            try {
                if (!token) {
                    console.warn('Save Task: no user token found; change will be local only.');
                    return;
                }
                const response = await fetch(`${API_BASE_URL}/tasks/${currentTaskToEdit._id}`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ description: newDescription })
                });

                if (!response.ok) {
                    let errText = `HTTP ${response.status}`;
                    try {
                        const errData = await response.json();
                        if (errData && (errData.error || errData.message)) errText += `: ${errData.error || errData.message}`;
                    } catch (parseErr) {
                        console.warn('Save Task: failed to parse server error JSON', parseErr);
                    }
                    console.warn('Save Task: server rejected update for task', currentTaskToEdit._id, errText);
                }
            } catch (err) {
                console.warn('Save Task: network error while saving task details (change kept locally):', err);
            }
        })();
    });
}

// --- ADMIN PANEL LOGIC ---

// Function to show the admin dashboard and hide the regular dashboard
function showAdminDashboard() {
    showPage('admin-dashboard-section', 'admin-panel-link');
    fetchAllUsers();
    fetchAllTasksForAdmin(); 
}

// Function to show the regular dashboard and hide the admin dashboard
function showRegularDashboard() {
    showPage('dashboard', 'dashboard-link');
    fetchTasks(); 
}

// Event listener for Admin Panel link
if (showAdminPanelBtn) {
    showAdminPanelBtn.addEventListener('click', (e) => {
        e.preventDefault();
        if (currentUserRole === 'admin') {
            showAdminDashboard();
        } else {
            showGenericModal("Access Denied", "You do not have administrative privileges.", [{ text: "OK", className: "vault-btn primary" }]);
        }
    });
}

// Event listener for Dashboard link
if (dashboardLink) {
    dashboardLink.addEventListener('click', (e) => {
        e.preventDefault();
        showRegularDashboard();
    });
}


// Fetches all users for admin view
const fetchAllUsers = async () => {
    const token = localStorage.getItem('userToken');
    if (!token || currentUserRole !== 'admin') {
        console.warn('Not authorized to fetch all users.');
        if (adminUsersList) adminUsersList.innerHTML = '<p class="placeholder-text">Access Denied: Admin privileges required.</p>';
        return;
    }

    if (adminUsersList) adminUsersList.innerHTML = '<p class="placeholder-text">Loading users...</p>'; 

    try {
        const response = await fetch(`${API_BASE_URL}/admin/users`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                showGenericModal("Access Denied", "You do not have permission to view users.", [{ text: "OK", className: "vault-btn primary" }]);
                if (adminUsersList) adminUsersList.innerHTML = '<p class="placeholder-text">Access Denied: Admin privileges required.</p>';
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const users = await response.json();
        renderUsersForAdmin(users);
    } catch (error) {
        console.error('Error fetching all users:', error);
        if (adminUsersList) adminUsersList.innerHTML = '<p class="placeholder-text">Failed to load users.</p>';
    }
};

// Renders users in the admin user list with role dropdown and save button
const renderUsersForAdmin = (users) => {
    if (!adminUsersList) return;
    adminUsersList.innerHTML = ''; 
    if (users.length === 0) {
        adminUsersList.innerHTML = '<p class="placeholder-text">No users found.</p>';
        return;
    }

    users.forEach(user => {
        const userCard = document.createElement('div');
        userCard.className = 'user-card task-card'; 
        userCard.innerHTML = `
            <h3>${user.email}</h3>
            <p>ID: ${user._id}</p>
            <div class="user-role-control">
                <label for="role-select-${user._id}">Role:</label>
                <select id="role-select-${user._id}" class="role-select ${user.role === 'admin' ? 'role-admin' : 'role-user'}">
                    <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                    <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                </select>
                <button class="save-role-btn vault-btn primary" data-user-id="${user._id}" data-original-role="${user.role}">Save Role</button>
            </div>
            <div class="user-actions">
                <button class="delete-user-btn" data-user-id="${user._id}" title="Delete User">Delete User</button>
            </div>
        `;
        adminUsersList.appendChild(userCard);

        // Add event listener for role select change to enable/disable save button
        const roleSelect = userCard.querySelector(`#role-select-${user._id}`);
        const saveRoleBtn = userCard.querySelector(`.save-role-btn`);

        // Disable save button initially if no change
        saveRoleBtn.disabled = true;

        roleSelect.addEventListener('change', () => {
            if (roleSelect.value !== saveRoleBtn.dataset.originalRole) {
                saveRoleBtn.disabled = false; 
                roleSelect.classList.remove('role-user', 'role-admin');
                roleSelect.classList.add(`role-${roleSelect.value}`);
            } else {
                saveRoleBtn.disabled = true; 
                roleSelect.classList.remove('role-user', 'role-admin');
                roleSelect.classList.add(`role-${roleSelect.value}`);
            }
        });
        
        // Delete User Button
        userCard.querySelector('.delete-user-btn').addEventListener('click', (e) => {
            const userIdToDelete = e.target.dataset.userId;
            showGenericModal(
                "Confirm User Deletion",
                `Are you sure you want to delete user: ${user.email}? This action cannot be undone.`,
                [
                    { text: "Delete User", className: "vault-btn primary", onClick: () => deleteUser(userIdToDelete) },
                    { text: "Cancel", className: "vault-btn secondary" }
                ]
            );
        });

        // Save Role Button
        saveRoleBtn.addEventListener('click', (e) => {
            const userIdToUpdate = e.target.dataset.userId;
            const newRole = roleSelect.value;
            showGenericModal(
                "Confirm Role Change",
                `Are you sure you want to change the role of ${user.email} to "${newRole}"?`,
                [
                    { text: "Change Role", className: "vault-btn primary", onClick: () => updateUserRole(userIdToUpdate, newRole) },
                    { text: "Cancel", className: "vault-btn secondary" }
                ]
            );
        });
    });
};

// Updates a user's role (admin action)
const updateUserRole = async (userId, newRole) => {
    const token = localStorage.getItem('userToken');
    if (!token || currentUserRole !== 'admin') {
        showGenericModal("Access Denied", "You do not have permission to change user roles.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/admin/users/${userId}/role`, { 
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ newRole })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        showGenericModal("Success", `User role updated to ${newRole}.`, [{ text: "OK", className: "vault-btn primary" }]);
        fetchAllUsers(); 
    } catch (error) {
        console.error('Error updating user role:', error);
        showGenericModal("Error", `Failed to update user role: ${error.message}`, [{ text: "OK", className: "vault-btn primary" }]);
    }
};


// Deletes a user (admin action)
const deleteUser = async (userId) => {
    const token = localStorage.getItem('userToken');
    if (!token || currentUserRole !== 'admin') {
        showGenericModal("Access Denied", "You do not have permission to delete users.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        showGenericModal("Success", "User deleted successfully.", [{ text: "OK", className: "vault-btn primary" }]);
        fetchAllUsers(); 
    } catch (error) {
        console.error('Error deleting user:', error);
        showGenericModal("Error", `Failed to delete user: ${error.message}`, [{ text: "OK", className: "vault-btn primary" }]);
    }
};

// Fetches all tasks for admin view (global tasks)
const fetchAllTasksForAdmin = async () => {
    const token = localStorage.getItem('userToken');
    if (!token || currentUserRole !== 'admin') {
        console.warn('Not authorized to fetch all tasks for admin.');
        if (adminAllTasksList) adminAllTasksList.innerHTML = '<p class="placeholder-text">Access Denied: Admin privileges required.</p>';
        return;
    }

    if (adminAllTasksList) adminAllTasksList.innerHTML = '<p class="placeholder-text">Loading all tasks...</p>'; 

    try {
        const response = await fetch(`${API_BASE_URL}/admin/tasks`, { 
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                showGenericModal("Access Denied", "You do not have permission to view all tasks.", [{ text: "OK", className: "vault-btn primary" }]);
                if (adminAllTasksList) adminAllTasksList.innerHTML = '<p class="placeholder-text">Access Denied: Admin privileges required.</p>';
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const tasks = await response.json();
        renderAllTasksForAdmin(tasks);
    } catch (error) {
        console.error('Error fetching all tasks for admin:', error);
        if (adminAllTasksList) adminAllTasksList.innerHTML = '<p class="placeholder-text">Failed to load all tasks.</p>';
    }
};

// Renders all tasks in the admin all tasks list
const renderAllTasksForAdmin = (tasks) => {
    if (!adminAllTasksList) return;
    adminAllTasksList.innerHTML = ''; 
    if (tasks.length === 0) {
        adminAllTasksList.innerHTML = '<p class="placeholder-text">No tasks found in the system.</p>';
        return;
    }

    tasks.forEach(task => {
        const taskCard = document.createElement('div');
        taskCard.className = `task-card priority-${task.priority.toLowerCase()}`;
        taskCard.id = `admin-task-${task._id}`; 
        
        const dueDate = task.due_date ? new Date(task.due_date).toLocaleDateString() : 'No Due Date';

        taskCard.innerHTML = `
            <h3>${task.title}</h3>
            <p>Status: ${task.status}</p>
            <p>Priority: ${task.priority}</p>
            <p>Due: ${dueDate}</p>
            <p>Created by: ${task.userEmail || 'N/A'}</p> <div class="task-actions">
                <button class="delete-admin-task-btn" data-task-id="${task._id}" title="Delete Task">×</button>
                </div>
        `;
        adminAllTasksList.appendChild(taskCard);
    });

    // Add event listeners for delete admin task buttons
    adminAllTasksList.querySelectorAll('.delete-admin-task-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const taskIdToDelete = e.target.dataset.taskId;
            showGenericModal(
                "Confirm Task Deletion (Admin)",
                `Are you sure you want to delete this task (ID: ${taskIdToDelete})? This will delete it for all users.`,
                [
                    { text: "Delete Task", className: "vault-btn primary", onClick: () => deleteAdminTask(taskIdToDelete) },
                    { text: "Cancel", className: "vault-btn secondary" }
                ]
            );
        });
    });
};

// Deletes any task (admin action)
const deleteAdminTask = async (taskId) => {
    const token = localStorage.getItem('userToken');
    if (!token || currentUserRole !== 'admin') {
        showGenericModal("Access Denied", "You do not have permission to delete tasks globally.", [{ text: "OK", className: "vault-btn primary" }]);
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/admin/tasks/${taskId}`, { 
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        showGenericModal("Success", "Task deleted successfully from all users.", [{ text: "OK", className: "vault-btn primary" }]);
        fetchAllTasksForAdmin(); 
    } catch (error) {
        console.error('Error deleting admin task:', error);
        showGenericModal("Error", `Failed to delete task: ${error.message}`, [{ text: "OK", className: "vault-btn primary" }]);
    }
};

// --- Profile Form & Data Logic ---

// Function to fetch and display user data
// --- ENHANCED Profile Form & Data Logic ---

// Get current user ID from localStorage
function getCurrentUserId() {
    const token = localStorage.getItem('userToken');
    if (token) {
        const decoded = decodeJwt(token);
        return decoded ? decoded._id : null;
    }
    return null;
}

// Get current user email from localStorage
function getCurrentUserEmail() {
    const token = localStorage.getItem('userToken');
    if (token) {
        const decoded = decodeJwt(token);
        return decoded ? decoded.email : '';
    }
    return '';
}

// Function to show the profile page
function showProfilePage() {
    showPage('profile-page', 'profile-link');
    loadUserProfile();
}

// Load user profile from database
async function loadUserProfile() {
    const userId = getCurrentUserId();
    const userEmail = getCurrentUserEmail();
    
    if (!userId) {
        displayMessage(profileMessage, 'Please log in first', 'error');
        return;
    }

    // Set email field (from token)
    if (profileEmailInput) profileEmailInput.value = userEmail;

    const token = localStorage.getItem('userToken');

    try {
        const response = await fetch(`${API_BASE_URL}/profile/${userId}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const profile = await response.json();
            
            // Fill form with existing profile data
            if (document.getElementById('profile-fullname')) {
                document.getElementById('profile-fullname').value = profile.fullName || '';
            }
            if (document.getElementById('profile-bio')) {
                document.getElementById('profile-bio').value = profile.bio || '';
            }
            if (document.getElementById('profile-phone')) {
                document.getElementById('profile-phone').value = profile.phoneNumber || '';
            }
            if (document.getElementById('profile-location')) {
                document.getElementById('profile-location').value = profile.location || '';
            }
            if (document.getElementById('profile-picture')) {
                document.getElementById('profile-picture').value = profile.profilePicture || '';
            }
            // Update avatar preview if picture URL exists
            if (typeof updateProfileAvatar === 'function') {
                updateProfileAvatar(profile.profilePicture || '');
            }
            
            if (profile.dateOfBirth && document.getElementById('profile-dob')) {
                const date = new Date(profile.dateOfBirth);
                document.getElementById('profile-dob').value = date.toISOString().split('T')[0];
            }
            
            // Update character count for bio
            updateBioCharCount();
        } else if (response.status === 404) {
            // Profile doesn't exist yet - that's okay
            console.log('No profile found, user can create one');
        } else {
            throw new Error('Failed to load profile');
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        displayMessage(profileMessage, 'Could not load profile.', 'error');
    }
}

// Save user profile to database
async function saveUserProfile(event) {
    event.preventDefault();

    const userId = getCurrentUserId();

    if (!userId) {
        displayMessage(profileMessage, 'Please log in first', 'error');
        return;
    }

    const saveBtn = document.getElementById('save-profile-btn');

    const formData = {
        userId: userId,
        fullName: document.getElementById('profile-fullname')?.value.trim() || '',
        bio: document.getElementById('profile-bio')?.value.trim() || '',
        phoneNumber: document.getElementById('profile-phone')?.value.trim() || '',
        location: document.getElementById('profile-location')?.value.trim() || '',
        profilePicture: document.getElementById('profile-picture')?.value.trim() || '',
        dateOfBirth: document.getElementById('profile-dob')?.value || ''
    };

    // Validate required fields
    if (!formData.fullName) {
        displayMessage(profileMessage, 'Full name is required', 'error');
        return;
    }

    // Show saving state in UI
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.dataset.orig = saveBtn.innerHTML;
        saveBtn.innerHTML = `<span class="btn-text">Saving...</span> <svg class="save-icon loading" xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><circle cx='12' cy='12' r='10'></circle><path d='M12 6v6l4 2'></path></svg>`;
    }

    displayMessage(profileMessage, 'Saving profile...', '');

    const token = localStorage.getItem('userToken');

    try {
        const response = await fetch(`${API_BASE_URL}/profile`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();

        if (response.ok) {
            displayMessage(profileMessage, result.message || 'Profile saved successfully!', 'success');
            // Show toast
            const toast = document.getElementById('profile-update-toast');
            if (toast) {
                toast.classList.remove('hidden');
                setTimeout(() => toast.classList.add('show'), 20);
                setTimeout(() => {
                    toast.classList.remove('show');
                    setTimeout(() => toast.classList.add('hidden'), 300);
                }, 3000);
            }
        } else {
            throw new Error(result.message || 'Failed to save profile');
        }
    } catch (error) {
        console.error('Error saving profile:', error);
        displayMessage(profileMessage, 'Could not save profile. Please try again.', 'error');
    } finally {
        // restore button
        if (saveBtn) {
            saveBtn.disabled = false;
            if (saveBtn.dataset.orig) {
                saveBtn.innerHTML = saveBtn.dataset.orig;
                delete saveBtn.dataset.orig;
            }
        }
    }
}

// Update bio character count
function updateBioCharCount() {
    const bioField = document.getElementById('profile-bio');
    const charCount = document.getElementById('bio-char-count');
    
    if (bioField && charCount) {
        charCount.textContent = `${bioField.value.length}/500 characters`;
    }
}


// Update profile avatar preview from a URL. Validates load before showing.
function updateProfileAvatar(url) {
    if (!profileAvatar || !profileAvatarImg) return;

    const trimmed = (url || '').trim();
    if (!trimmed) {
        profileAvatarImg.src = '';
        profileAvatar.classList.remove('has-image');
        return;
    }

    // Validate by attempting to load the image first
    const validationImg = new Image();
    validationImg.onload = () => {
        profileAvatarImg.src = trimmed;
        profileAvatar.classList.add('has-image');
    };
    validationImg.onerror = () => {
        // invalid image — fall back to placeholder
        profileAvatarImg.src = '';
        profileAvatar.classList.remove('has-image');
    };
    validationImg.src = trimmed;
}
// --- END ENHANCED Profile Functions ---

// Event listener for the Profile link
if (profileLink) {
    profileLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (userDropdownMenu) userDropdownMenu.classList.add('hidden'); 
        if (userMenuButton) userMenuButton.classList.remove('active'); 
        showProfilePage(); // Use the new function that loads profile data
    });
}
// Update sign out logic to use the new dropdown link
if (signoutLink) {
    signoutLink.addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.removeItem('userToken');
        showLogin();
        // userEmailDisplay.textContent = ''; // Clear the user email display in the header on signout
    });
}
// --- Profile Form Submission Logic ---
if (profileForm) {
    profileForm.addEventListener('submit', saveUserProfile); // Use the new function
}
// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    if (copyrightYear) copyrightYear.textContent = new Date().getFullYear();
    checkAuthStatus(); // Call this once to check initial auth state

    // Add the event listener for the unlock button
    if (unlockButton) {
        unlockButton.addEventListener('click', () => {
            if (loginWindow) loginWindow.classList.add('expanded');
            if (loginFormWrapper) loginFormWrapper.classList.remove('collapsed');
        });
    }

    // --- NAVIGATION LISTENERS (for Admin and Files) ---
    // ... (Keep all your existing navigation listeners here) ...

    if (dashboardLink) {
        dashboardLink.addEventListener('click', (e) => {
            e.preventDefault();
            showRegularDashboard(); 
        });
    }
    
    if (adminPanelLink) {
        adminPanelLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (currentUserRole === 'admin') {
                showAdminDashboard(); 
            } else {
                showGenericModal("Access Denied", "You do not have administrative privileges to view this panel.", [{ text: "OK", className: "vault-btn primary" }]);
            }
        });
    }

    if (fileStorageLink) {
        fileStorageLink.addEventListener('click', (e) => {
            e.preventDefault();
            showPage('file-storage-page', 'file-storage-link'); 
            fetchStoredFiles(); 
        });
    }
    
    // NOTE: privateVaultLink intentionally removed per user request.
    // --- END OF NAVIGATION FIXES ---

    // Add event listener for the user menu button on the dashboard
    if (userMenuButton) {
        userMenuButton.addEventListener('click', (e) => {
            e.stopPropagation(); 
            if (userDropdownMenu) userDropdownMenu.classList.toggle('hidden');
        });
    }

    // Close the user dropdown if the user clicks anywhere else
    document.addEventListener('click', (e) => {
        if (userMenuButton && userDropdownMenu && !userMenuButton.contains(e.target) && !userDropdownMenu.contains(e.target)) {
            userDropdownMenu.classList.add('hidden');
        }
    });

    // Disable dates before the current day in the task due date calendar
    const today = new Date().toISOString().split('T')[0];
    const dueDateInput = document.getElementById('task-due-date');
    if (dueDateInput) {
        dueDateInput.setAttribute('min', today);
    }

    // =======================================================
    // === FIX: STANDARD FILE UPLOAD LISTENERS (External) ===
    // =======================================================
    
    // 1. Standard File Upload Button Listener (Handles both click-to-select and click-to-upload)
    if (triggerUploadBtn) {
        // Log removed to minimize console clutter, but logic is sound:
        triggerUploadBtn.addEventListener('click', () => {
            if (filesToUploadQueue.length > 0) {
                // Files are staged from file dialog or drag/drop, proceed to upload
                uploadFiles(filesToUploadQueue);
            } else {
                // No files staged, trigger the file selection dialog
                // Since manual click works, this must work too.
              fileUploadInput.click();
            }
        });
        triggerUploadBtn.disabled = true; 
    }

    // 2. Standard File Input Change Listener (stages files)
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', (e) => {
            const files = e.target.files;
            if (files.length > 0) {
                handleFiles(Array.from(files)); // Stages the files and enables the button
            }
        });
    }

    // 3. Standard Drag and Drop Handlers (Already correct, calling handleFiles)
    if (dropZone) {
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        function handleDrop(e) {
            preventDefaults(e);
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(Array.from(files));
            dropZone.classList.remove('highlight');
        }

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('highlight'), false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('highlight'), false);
        });

        dropZone.addEventListener('drop', handleDrop, false);
    }
    
    // Profile picture live preview: update avatar as user types a URL
    if (profilePictureInput) {
        profilePictureInput.addEventListener('input', (e) => {
            try { updateProfileAvatar(e.target.value || ''); } catch (err) { /* ignore */ }
        });
        profilePictureInput.addEventListener('blur', (e) => {
            try { updateProfileAvatar(e.target.value || ''); } catch (err) { /* ignore */ }
        });
        // If an initial value exists (e.g., from server), preview it
        if (profilePictureInput.value) {
            try { updateProfileAvatar(profilePictureInput.value); } catch (err) { /* ignore */ }
        }
    }
        // Wire email validation for signin/signup inputs
        try { wireEmailValidationInputs(); } catch (err) { /* ignore */ }
    // =======================================================
    // === END OF STANDARD FILE UPLOAD FIXES ===
    // =======================================================

    // --- SECRET VAULT LOGIC INTEGRATION (Forms and Trigger) ---

    // --- Vault Setup Form Submission ---
    if (vaultSetupForm) {
        vaultSetupForm.addEventListener('submit', setupVault); // Uses global setupVault function
    }

    // --- Vault Unlock Form Submission ---
    if (vaultUnlockForm) {
        vaultUnlockForm.addEventListener('submit', unlockVault); // Uses global unlockVault function
    }

    // --- Close Vault Button ---
    if (closeSecretVaultBtn) {
        closeSecretVaultBtn.addEventListener('click', () => {
            if (secretVaultModal) secretVaultModal.classList.add('hidden');
            vaultAccessKey = null; // IMPORTANT: Clear key on modal close
            if (vaultUnlockForm) vaultUnlockForm.reset();
            if (vaultSetupForm) vaultSetupForm.reset();
            if (vaultFileListDisplay) vaultFileListDisplay.innerHTML = '';
        });
    }
    
    // --- VAULT FILE UPLOAD LISTENERS (Inside Modal) ---
    if (vaultTriggerUploadBtn && vaultFileInput) {
        vaultTriggerUploadBtn.addEventListener('click', () => {
            if (vaultAccessKey) { 
                vaultFileInput.click();
            } else {
                showGenericModal("Vault Locked", "Please unlock the vault before uploading files.", [{ text: "OK", className: "vault-btn primary" }]);
            }
        });
    }

    if (vaultFileInput) {
        vaultFileInput.addEventListener('change', (e) => {
            const files = e.target.files;
            if (files.length > 0) {
                if (vaultFileListDisplay) {
                    vaultFileListDisplay.innerHTML = ''; // Clear existing file list display
                    Array.from(files).forEach(file => {
                        const li = document.createElement('li');
                        li.textContent = `• ${file.name} (${(file.size / 1024).toFixed(2)} KB) - Encrypting...`;
                        if(vaultFileListDisplay) vaultFileListDisplay.appendChild(li);
                    });
                }
                uploadSecretFiles(Array.from(files));
            }
        });
    }
    
    // --- Vault Drag and Drop Handlers (Corrected) ---
    if (vaultDropZone) {
        
        function vaultPreventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        function vaultHandleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            vaultPreventDefaults(e);

            if (vaultAccessKey) {
                // Display files in the drop zone and start upload
                if (vaultFileListDisplay) {
                     vaultFileListDisplay.innerHTML = ''; 
                     Array.from(files).forEach(file => {
                         const li = document.createElement('li');
                         li.textContent = `• ${file.name} (${(file.size / 1024).toFixed(2)} KB) - Encrypting...`;
                         vaultFileListDisplay.appendChild(li);
                     });
                }
                uploadSecretFiles(Array.from(files));
            } else {
                showGenericModal("Vault Locked", "Please unlock the vault before dropping files.", [{ text: "OK", className: "vault-btn primary" }]);
            }
        }
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            vaultDropZone.addEventListener(eventName, vaultPreventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            vaultDropZone.addEventListener(eventName, () => vaultDropZone.classList.add('highlight'), false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            vaultDropZone.addEventListener(eventName, () => vaultDropZone.classList.remove('highlight'), false);
        });

        vaultDropZone.addEventListener('drop', vaultHandleDrop, false);
    }
    const bioField = document.getElementById('profile-bio');
    if (bioField) {
        bioField.addEventListener('input', updateBioCharCount);
    }
    // ========================================
// PRIVATE VAULT FUNCTIONALITY
// ========================================

// Private Vault State
let privateVaultKey = null;
let privateVaultFiles = [];
let privateVaultPasswords = [];

// DOM Elements for Private Vault
const privateVaultModal = document.getElementById('private-vault-modal');
const closePrivateVaultBtn = document.getElementById('close-private-vault-btn');
const privateVaultSetupView = document.getElementById('private-vault-setup-view');
const privateVaultUnlockView = document.getElementById('private-vault-unlock-view');
const privateVaultContentView = document.getElementById('private-vault-content-view');
const privateVaultSetupForm = document.getElementById('private-vault-setup-form');
const privateVaultUnlockForm = document.getElementById('private-vault-unlock-form');
const lockPrivateVaultBtn = document.getElementById('lock-private-vault-btn');
const privateVaultFileInput = document.getElementById('private-vault-file-input');
const privateVaultUploadBtn = document.getElementById('private-vault-upload-btn');
const privateVaultAddPasswordForm = document.getElementById('private-vault-add-password-form');

// Simple Encryption Functions (Caesar Cipher + Base64)
function simpleEncrypt(text, password) {
    const shift = password.length;
    const shifted = text.split('').map(c => 
        String.fromCharCode(c.charCodeAt(0) + shift)
    ).join('');
    return btoa(shifted);
}

function simpleDecrypt(encrypted, password) {
    try {
        const shift = password.length;
        const decoded = atob(encrypted);
        return decoded.split('').map(c => 
            String.fromCharCode(c.charCodeAt(0) - shift)
        ).join('');
    } catch (e) {
        return null;
    }
}

// Load Private Vault Data from localStorage
function loadPrivateVaultData() {
    const masterPasswordHash = localStorage.getItem('privateVaultMasterPasswordHash');
    const filesData = localStorage.getItem('privateVaultFiles');
    const passwordsData = localStorage.getItem('privateVaultPasswords');
    
    if (filesData) {
        try {
            privateVaultFiles = JSON.parse(filesData);
        } catch (e) {
            privateVaultFiles = [];
        }
    }
    
    if (passwordsData) {
        try {
            privateVaultPasswords = JSON.parse(passwordsData);
        } catch (e) {
            privateVaultPasswords = [];
        }
    }
    
    return !!masterPasswordHash;
}

// Save Private Vault Data to localStorage
function savePrivateVaultData() {
    localStorage.setItem('privateVaultFiles', JSON.stringify(privateVaultFiles));
    localStorage.setItem('privateVaultPasswords', JSON.stringify(privateVaultPasswords));
}

// === Modern encryption helpers using Web Crypto (AES-GCM with PBKDF2) ===
function bufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const slice = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode.apply(null, slice);
    }
    return btoa(binary);
}

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const pwKey = await window.crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return window.crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt,
        iterations: 150000,
        hash: 'SHA-256'
    }, pwKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptArrayBuffer(arrayBuffer, password) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt.buffer);
    const cipher = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, arrayBuffer);
    // Store salt + iv + cipher
    const saltIvCipher = new Uint8Array(salt.byteLength + iv.byteLength + cipher.byteLength);
    saltIvCipher.set(salt, 0);
    saltIvCipher.set(iv, salt.byteLength);
    saltIvCipher.set(new Uint8Array(cipher), salt.byteLength + iv.byteLength);
    return bufferToBase64(saltIvCipher.buffer);
}

async function decryptArrayBuffer(base64String, password) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const buf = base64ToBuffer(base64String);
    const bytes = new Uint8Array(buf);
    const salt = bytes.slice(0, 16);
    const iv = bytes.slice(16, 28);
    const cipher = bytes.slice(28).buffer;
    const key = await deriveKey(password, salt.buffer);
    const plain = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    return plain; // ArrayBuffer
}


// Double-Tap Detection on Logo
let logoTapCount = 0;
let logoTapTimer = null;

if (logo) {
    logo.addEventListener('click', () => {
        logoTapCount++;
        
        if (logoTapTimer) clearTimeout(logoTapTimer);
        
        if (logoTapCount === 2) {
            // Double-tap detected!
            logoTapCount = 0;
            openPrivateVault();
        } else {
            logoTapTimer = setTimeout(() => {
                logoTapCount = 0;
            }, 500);
        }
    });
}

// Open Private Vault Modal
function openPrivateVault() {
    const token = localStorage.getItem('userToken');
    if (!token) {
        showGenericModal("Sign In Required", "Please sign in to access the Private Vault.", [
            { text: "OK", className: "vault-btn primary" }
        ]);
        return;
    }
    
    const isSetup = loadPrivateVaultData();
    
    if (!isSetup) {
        // Show setup view
        privateVaultSetupView.classList.remove('hidden');
        privateVaultUnlockView.classList.add('hidden');
        privateVaultContentView.classList.add('hidden');
    } else {
        // Show unlock view
        privateVaultSetupView.classList.add('hidden');
        privateVaultUnlockView.classList.remove('hidden');
        privateVaultContentView.classList.add('hidden');
    }
    
    privateVaultModal.classList.remove('hidden');
}

// Close Private Vault Modal
if (closePrivateVaultBtn) {
    closePrivateVaultBtn.addEventListener('click', () => {
        privateVaultModal.classList.add('hidden');
        clearPrivateVaultInputs();
    });
}

// Clear Input Fields
function clearPrivateVaultInputs() {
    if (document.getElementById('private-vault-password-new')) {
        document.getElementById('private-vault-password-new').value = '';
    }
    if (document.getElementById('private-vault-password-confirm')) {
        document.getElementById('private-vault-password-confirm').value = '';
    }
    if (document.getElementById('private-vault-password-unlock')) {
        document.getElementById('private-vault-password-unlock').value = '';
    }
}

// Setup Private Vault
if (privateVaultSetupForm) {
    privateVaultSetupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const password = document.getElementById('private-vault-password-new').value;
        const confirmPassword = document.getElementById('private-vault-password-confirm').value;
        const messageEl = document.getElementById('private-vault-setup-message');
        
        if (password.length < 4) {
            displayMessage(messageEl, 'Password must be at least 4 characters!', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            displayMessage(messageEl, 'Passwords do not match!', 'error');
            return;
        }
        
        // Hash and store master password
        const hashedPassword = await hashString(password);
        localStorage.setItem('privateVaultMasterPasswordHash', hashedPassword);
        
        privateVaultKey = password;
        
        displayMessage(messageEl, '✅ Vault created successfully!', 'success');
        
        setTimeout(() => {
            showPrivateVaultContent();
        }, 1000);
    });
}

// Unlock Private Vault
if (privateVaultUnlockForm) {
    privateVaultUnlockForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const password = document.getElementById('private-vault-password-unlock').value;
        const messageEl = document.getElementById('private-vault-unlock-message');
        
        const hashedPassword = await hashString(password);
        const storedHash = localStorage.getItem('privateVaultMasterPasswordHash');
        
        if (hashedPassword === storedHash) {
            privateVaultKey = password;
            displayMessage(messageEl, '✅ Vault unlocked!', 'success');
            
            setTimeout(() => {
                showPrivateVaultContent();
            }, 500);
        } else {
            displayMessage(messageEl, '❌ Wrong password!', 'error');
        }
    });
}

// Show Vault Content
function showPrivateVaultContent() {
    privateVaultSetupView.classList.add('hidden');
    privateVaultUnlockView.classList.add('hidden');
    privateVaultContentView.classList.remove('hidden');
    
    renderPrivateVaultFiles();
    renderPrivateVaultPasswords();
}

// Lock Vault
if (lockPrivateVaultBtn) {
    lockPrivateVaultBtn.addEventListener('click', () => {
        privateVaultKey = null;
        privateVaultModal.classList.add('hidden');
        clearPrivateVaultInputs();
    });
}

// Tab Switching
const vaultTabs = document.querySelectorAll('.vault-tab');
const vaultFilesTab = document.getElementById('vault-files-tab');
const vaultPasswordsTab = document.getElementById('vault-passwords-tab');

vaultTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        
        // Update active tab
        vaultTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Show/hide content
        if (tabName === 'files') {
            vaultFilesTab.classList.remove('hidden');
            vaultPasswordsTab.classList.add('hidden');
        } else {
            vaultFilesTab.classList.add('hidden');
            vaultPasswordsTab.classList.remove('hidden');
        }
    });
});

// File Upload
if (privateVaultUploadBtn && privateVaultFileInput) {
    privateVaultUploadBtn.addEventListener('click', () => {
        privateVaultFileInput.click();
    });
    
    privateVaultFileInput.addEventListener('change', async (e) => {
        const files = e.target.files;
        if (!files || files.length === 0) return;
        if (!privateVaultKey) return;
        
        for (const file of files) {
            // Read as ArrayBuffer for binary-safe encryption
            const arrayBuf = await file.arrayBuffer();
            let storedContent = null;
            try {
                if (window.crypto && window.crypto.subtle) {
                    storedContent = await encryptArrayBuffer(arrayBuf, privateVaultKey); // base64
                } else {
                    // Fallback: read as text and use simpleEncrypt
                    const text = new TextDecoder().decode(arrayBuf);
                    storedContent = simpleEncrypt(text, privateVaultKey);
                }
            } catch (err) {
                console.error('Private Vault: encryption failed for file', file.name, err);
                continue; // Skip this file
            }

            privateVaultFiles.push({
                id: Date.now() + Math.random(),
                name: file.name,
                size: file.size,
                type: file.type,
                content: storedContent,
                encrypted: true,
                date: new Date().toISOString()
            });

            savePrivateVaultData();
            renderPrivateVaultFiles();
        }
        
        privateVaultFileInput.value = '';
    });
}

// Render Files
function renderPrivateVaultFiles() {
    const list = document.getElementById('private-vault-files-list');
    if (!list) return;
    
    if (privateVaultFiles.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No encrypted files yet.</p>';
        return;
    }
    
    list.innerHTML = '';
    
    privateVaultFiles.forEach(file => {
        const item = document.createElement('div');
        item.className = 'vault-file-item';
        
        const fileSize = (file.size / 1024).toFixed(2);
        const fileDate = new Date(file.date).toLocaleDateString();
        
        item.innerHTML = `
            <div class="vault-item-info">
                <div class="vault-item-name">📄 ${file.name}</div>
                <div class="vault-item-meta">${fileSize} KB • ${fileDate}</div>
            </div>
            <div class="vault-item-actions">
                <button class="vault-action-btn download" onclick="downloadPrivateVaultFile(${file.id})">⬇️ Download</button>
                <button class="vault-action-btn delete" onclick="deletePrivateVaultFile(${file.id})">🗑️ Delete</button>
            </div>
        `;
        
        list.appendChild(item);
    });
}

// Download File
window.downloadPrivateVaultFile = function(fileId) {
    const file = privateVaultFiles.find(f => f.id === fileId);
    if (!file || !privateVaultKey) return;
    (async () => {
        try {
            if (window.crypto && window.crypto.subtle && file.encrypted) {
                const plainBuf = await decryptArrayBuffer(file.content, privateVaultKey);
                if (!plainBuf) throw new Error('Decryption returned null');
                const blob = new Blob([plainBuf], { type: file.type || 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = file.name;
                a.click();
                URL.revokeObjectURL(url);
            } else {
                // Fallback: assume text content encrypted with simpleEncrypt
                const decryptedContent = simpleDecrypt(file.content, privateVaultKey);
                if (!decryptedContent) throw new Error('Failed to decrypt file with fallback');
                const blob = new Blob([decryptedContent], { type: file.type || 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = file.name;
                a.click();
                URL.revokeObjectURL(url);
            }
        } catch (err) {
            console.error('Error during private file download/decryption:', err);
            showGenericModal("Error", "Failed to decrypt or download file.", [{ text: "OK", className: "vault-btn primary" }]);
        }
    })();
};

// Delete File
window.deletePrivateVaultFile = function(fileId) {
    if (!confirm('Delete this file?')) return;
    
    privateVaultFiles = privateVaultFiles.filter(f => f.id !== fileId);
    savePrivateVaultData();
    renderPrivateVaultFiles();
};

// Add Password
if (privateVaultAddPasswordForm) {
    privateVaultAddPasswordForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const name = document.getElementById('vault-pwd-name').value.trim();
        const username = document.getElementById('vault-pwd-username').value.trim();
        const password = document.getElementById('vault-pwd-password').value;
        
        if (!name || !password) return;
        
        const encryptedPassword = simpleEncrypt(password, privateVaultKey);
        
        privateVaultPasswords.push({
            id: Date.now() + Math.random(),
            name,
            username,
            password: encryptedPassword,
            date: new Date().toISOString()
        });
        
        savePrivateVaultData();
        renderPrivateVaultPasswords();
        
        privateVaultAddPasswordForm.reset();
    });
}

// Render Passwords
function renderPrivateVaultPasswords() {
    const list = document.getElementById('private-vault-passwords-list');
    if (!list) return;
    
    if (privateVaultPasswords.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No passwords saved yet.</p>';
        return;
    }
    
    list.innerHTML = '';
    
    privateVaultPasswords.forEach(pwd => {
        const item = document.createElement('div');
        item.className = 'vault-password-item';
        
        const pwdDate = new Date(pwd.date).toLocaleDateString();
        
        item.innerHTML = `
            <div class="vault-password-details">
                <div class="vault-item-name">🔑 ${pwd.name}</div>
                ${pwd.username ? `<div class="vault-username">👤 ${pwd.username}</div>` : ''}
                <div class="vault-password-value">
                    <span id="pwd-${pwd.id}">••••••••</span>
                    <button class="vault-action-btn show" onclick="togglePrivateVaultPassword(${pwd.id})">👁️</button>
                </div>
                <div class="vault-item-meta">Added: ${pwdDate}</div>
            </div>
            <div class="vault-item-actions">
                <button class="vault-action-btn delete" onclick="deletePrivateVaultPassword(${pwd.id})">🗑️ Delete</button>
            </div>
        `;
        
        list.appendChild(item);
    });
}

// Toggle Password Visibility
window.togglePrivateVaultPassword = function(pwdId) {
    const pwd = privateVaultPasswords.find(p => p.id === pwdId);
    if (!pwd || !privateVaultKey) return;
    
    const span = document.getElementById(`pwd-${pwdId}`);
    if (!span) return;
    
    if (span.textContent === '••••••••') {
        const decrypted = simpleDecrypt(pwd.password, privateVaultKey);
        span.textContent = decrypted || 'Error';
    } else {
        span.textContent = '••••••••';
    }
};

// Delete Password
window.deletePrivateVaultPassword = function(pwdId) {
    if (!confirm('Delete this password?')) return;
    
    privateVaultPasswords = privateVaultPasswords.filter(p => p.id !== pwdId);
    savePrivateVaultData();
    renderPrivateVaultPasswords();
};

document.addEventListener("DOMContentLoaded", function() {
  const vaultSetupForm = document.getElementById('private-vault-setup-form');
  if (vaultSetupForm) {
    vaultSetupForm.addEventListener('submit', function(event) {
      event.preventDefault(); // Prevents page reload
      const newPass = document.getElementById('private-vault-password-new').value.trim();
      const confirmPass = document.getElementById('private-vault-password-confirm').value.trim();
      const message = document.getElementById('private-vault-setup-message');

      if (newPass.length < 4) {
        message.textContent = 'Password must be at least 4 characters.';
        return;
      }
      if (newPass !== confirmPass) {
        message.textContent = 'Passwords do not match.';
        return;
      }

      // Save password securely (temporary - we’ll encrypt it later)
            // Store a hashed master password for the private vault
            (async () => {
                const hashed = await hashString(newPass);
                localStorage.setItem('privateVaultMasterPasswordHash', hashed);
                // Also set the runtime key for this session
                privateVaultKey = newPass;

                message.textContent = 'Vault created successfully!';
                document.getElementById('private-vault-setup-view').classList.add('hidden');
                document.getElementById('private-vault-unlock-view').classList.remove('hidden');
            })();
    });
  }
});

});