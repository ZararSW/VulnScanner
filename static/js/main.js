/**
 * Main JavaScript for Bug Hunter Vulnerability Scanner
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Form validation for the scan form
    const scanForm = document.querySelector('form[action*="scan"]');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            const targetUrl = document.getElementById('target_url').value;
            
            // Simple URL validation
            if (!targetUrl || !targetUrl.match(/^https?:\/\/.+/)) {
                event.preventDefault();
                alert('Please enter a valid URL starting with http:// or https://');
                return false;
            }
            
            // Display loading state
            const submitButton = scanForm.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Starting Scan...';
                submitButton.disabled = true;
            }
            
            return true;
        });
    }

    // Dynamic text truncation for URLs
    function truncateText() {
        const elements = document.querySelectorAll('.text-truncate');
        elements.forEach(function(element) {
            // Set a tooltip with the full text
            if (element.title === '') {
                element.title = element.textContent;
            }
        });
    }
    
    truncateText();
    
    // Handle copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-copy]');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            navigator.clipboard.writeText(textToCopy)
                .then(() => {
                    // Show success message
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check me-1"></i> Copied!';
                    
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                })
                .catch(err => {
                    console.error('Failed to copy text: ', err);
                });
        });
    });
    
    // Custom validation styles
    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach(function(input) {
        input.addEventListener('blur', function() {
            if (this.checkValidity()) {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
            } else {
                this.classList.remove('is-valid');
                this.classList.add('is-invalid');
            }
        });
    });
    
    // Handle accordion state persistence
    const accordions = document.querySelectorAll('.accordion-collapse');
    accordions.forEach(function(accordion) {
        accordion.addEventListener('shown.bs.collapse', function() {
            localStorage.setItem(this.id, 'open');
        });
        
        accordion.addEventListener('hidden.bs.collapse', function() {
            localStorage.removeItem(this.id);
        });
        
        // Restore state
        if (localStorage.getItem(accordion.id) === 'open') {
            new bootstrap.Collapse(accordion).show();
        }
    });
});

/**
 * Formats a date string for display
 * @param {string} dateString - The date string to format
 * @returns {string} Formatted date string
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}

/**
 * Updates the progress bar for a scan
 * @param {Element} progressBar - The progress bar element
 * @param {number} progress - Progress percentage (0-100)
 */
function updateProgressBar(progressBar, progress) {
    if (!progressBar) return;
    
    progressBar.style.width = progress + '%';
    progressBar.setAttribute('aria-valuenow', progress);
    progressBar.textContent = progress + '%';
    
    if (progress >= 100) {
        progressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
        progressBar.classList.add('bg-success');
    }
}
