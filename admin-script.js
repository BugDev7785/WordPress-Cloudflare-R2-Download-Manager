jQuery(document).ready(function($) {
    // Initialize notification system
    setupNotificationSystem();
    
    // Add form submission handlers
    setupFormHandlers();
    
    // File upload form handler
    $('#r2-upload-form').on('submit', function(e) {
        e.preventDefault();
        
        var fileInput = $('#r2-file-input')[0];
        if (fileInput.files.length === 0) {
            showNotification('error', 'Please select a file to upload.');
            return;
        }
        
        var formData = new FormData();
        formData.append('action', 'upload_to_r2');
        formData.append('security', wpCloudflareR2Ajax.nonce);
        formData.append('file', fileInput.files[0]);
        
        // Show progress
        $('#r2-upload-progress').removeClass('hidden');
        var $progressFill = $('.progress-bar-fill');
        var $progressText = $('.progress-text');
        $progressFill.css('width', '0%');
        $progressText.text('Uploading: 0%');
        
        // AJAX upload with progress
        $.ajax({
            url: wpCloudflareR2Ajax.ajaxurl,
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            xhr: function() {
                var xhr = new window.XMLHttpRequest();
                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        var percent = Math.round((e.loaded / e.total) * 100);
                        $progressFill.css('width', percent + '%');
                        $progressText.text('Uploading: ' + percent + '%');
                    }
                }, false);
                return xhr;
            },
            success: function(response) {
                // Hide progress and reset form
                $('#r2-upload-progress').addClass('hidden');
                $('#r2-upload-form')[0].reset();
                
                // Show result
                var resultDiv = $('#r2-upload-result');
                if (response.success) {
                    resultDiv.removeClass('error').addClass('success');
                    resultDiv.html('<div class="dashicons dashicons-yes-alt"></div> ' + response.data);
                    showNotification('success', wpCloudflareR2Ajax.messages.upload_success);
                } else {
                    resultDiv.removeClass('success').addClass('error');
                    resultDiv.html('<div class="dashicons dashicons-warning"></div> ' + response.data);
                    showNotification('error', wpCloudflareR2Ajax.messages.upload_error);
                }
                
                // Fade out result after 5 seconds
                setTimeout(function() {
                    resultDiv.fadeOut(300, function() {
                        $(this).html('').removeClass('success error').show();
                    });
                }, 5000);
            },
            error: function() {
                $('#r2-upload-progress').addClass('hidden');
                showNotification('error', wpCloudflareR2Ajax.messages.upload_error);
            }
        });
    });
    
    // Handle file input change to show selected filename
    $('#r2-file-input').on('change', function() {
        var fileName = $(this).val().split('\\').pop();
        if (fileName) {
            $('.file-input-label').text(fileName);
        } else {
            $('.file-input-label').html('<span class="dashicons dashicons-upload"></span> Choose File');
        }
    });
    
    // Initialize file input label with icon
    $('.file-input-label').html('<span class="dashicons dashicons-upload"></span> Choose File');
    
    // Add download button click handler with improved feedback
    $(document).on('click', '.r2-download-button', function() {
        var $button = $(this);
        var filename = $button.data('filename');
        var buttonText = $button.text().trim();
        
        // Store original text if not already stored
        if (!$button.attr('data-original-text')) {
            $button.attr('data-original-text', buttonText);
        } else {
            buttonText = $button.attr('data-original-text');
        }
        
        // Prevent multiple clicks
        if ($button.hasClass('downloading')) {
            return;
        }
        
        // Mark as downloading and replace text with spinning icon
        $button.addClass('downloading');
        $button.html('<span class="dashicons dashicons-update-alt spinning"></span>');
        
        var data = {
            'action': 'download_from_r2',
            'filename': filename,
            'security': wpCloudflareR2Ajax.nonce
        };
        
        $.post(wpCloudflareR2Ajax.ajaxurl, data, function(response) {
            if (response.success) {
                // Create temporary link and trigger download
                var a = document.createElement('a');
                a.href = response.data.download_url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                
                // Reset button after download starts
                setTimeout(function() {
                    $button.removeClass('downloading');
                    $button.html(buttonText);
                }, 1500);
            } else {
                showNotification('error', wpCloudflareR2Ajax.messages.download_error);
                
                // Reset button on error
                $button.removeClass('downloading');
                $button.html(buttonText);
            }
        }).fail(function() {
            showNotification('error', wpCloudflareR2Ajax.messages.download_error);
            
            // Reset button on failure
            $button.removeClass('downloading');
            $button.html(buttonText);
        });
    });

    // Enhanced copy link button functionality
    $(document).on('click', '.r2-copy-link', function() {
        var $button = $(this);
        var $input = $button.siblings('.r2-download-link');
        
        // Prevent multiple clicks
        if ($button.hasClass('copying')) {
            return;
        }
        
        // Set copying state
        $button.addClass('copying');
        
        // Modern clipboard API with fallback
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText($input.val())
                .then(function() {
                    showCopySuccess($button);
                })
                .catch(function() {
                    // Fallback to old method if clipboard API fails
                    legacyCopy($input, $button);
                });
        } else {
            // Fallback for browsers without clipboard API
            legacyCopy($input, $button);
        }
    });
    
    // Helper function for copy success feedback
    function showCopySuccess($button) {
        $button.text('Copied!');
        showNotification('success', wpCloudflareR2Ajax.messages.copy_success);
        
        setTimeout(function() {
            $button.text('Copy');
            $button.removeClass('copying');
        }, 2000);
    }
    
    // Legacy copy method
    function legacyCopy($input, $button) {
        $input.select();
        
        try {
            var successful = document.execCommand('copy');
            if (successful) {
                showCopySuccess($button);
            } else {
                $button.text('Failed');
                $button.removeClass('copying');
            }
        } catch (err) {
            $button.text('Failed');
            $button.removeClass('copying');
        }
    }

    // Update download links when page loads
    $('.r2-download-link').each(function() {
        var $input = $(this);
        var filename = $input.siblings('.r2-copy-link').data('filename');
        
        if (!filename) return;
        
        var data = {
            'action': 'download_from_r2',
            'filename': filename,
            'security': wpCloudflareR2Ajax.nonce
        };
        
        $.post(wpCloudflareR2Ajax.ajaxurl, data, function(response) {
            if (response.success) {
                $input.val(response.data.download_url);
            }
        });
    });
    
    // Set text for any empty buttons
    $('.r2-copy-link').each(function() {
        if ($(this).text().trim() === '') {
            $(this).text('Copy');
        }
    });
    
    $('.r2-download-button').each(function() {
        if ($(this).text().trim() === '') {
            $(this).text('Download');
        }
    });
    
    // Enhance access control form - with simpler approach
    $('#role-permissions-form').on('submit', function() {
        // Just store notification state for after redirect
        localStorage.setItem('r2_access_updated', 'true');
        // Allow form to submit normally
        return true;
    });
    
    /**
     * Setup notification system
     */
    function setupNotificationSystem() {
        // Create notification container if it doesn't exist
        if ($('#r2-notification-container').length === 0) {
            $('body').append('<div id="r2-notification-container"></div>');
        }
        
        // Check for URL parameters for success messages
        var urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('settings-updated') && urlParams.get('settings-updated') === 'true') {
            showNotification('success', wpCloudflareR2Ajax.messages.settings_saved);
        }
    }
    
    /**
     * Show notification
     * @param {string} type - success, error, or info
     * @param {string} message - Notification message
     */
    function showNotification(type, message) {
        var iconClass = 'dashicons-info';
        if (type === 'success') {
            iconClass = 'dashicons-yes-alt';
        } else if (type === 'error') {
            iconClass = 'dashicons-warning';
        }
        
        var notificationId = 'r2-notification-' + Date.now();
        var notification = $('<div class="r2-notification ' + type + '" id="' + notificationId + '">' +
                            '<div class="r2-notification-icon"><span class="dashicons ' + iconClass + '"></span></div>' +
                            '<div class="r2-notification-message">' + message + '</div>' +
                            '</div>');
        
        $('#r2-notification-container').append(notification);
        
        // Show notification with animation
        setTimeout(function() {
            $('#' + notificationId).addClass('show');
        }, 10);
        
        // Hide notification after 4 seconds
        setTimeout(function() {
            $('#' + notificationId).removeClass('show');
            
            // Remove from DOM after animation completes
            setTimeout(function() {
                $('#' + notificationId).remove();
            }, 300);
        }, 4000);
    }
    
    /**
     * Setup form submission handlers to show notifications
     */
    function setupFormHandlers() {
        // Add save feedback to main settings form
        $('form').on('submit', function() {
            // Store that we submitted the form, for notification after redirect
            if ($(this).attr('action') === 'options.php') {
                localStorage.setItem('r2_settings_updated', 'true');
            }
        });
        
        // Check if we need to show settings saved notification from localStorage
        if (localStorage.getItem('r2_settings_updated') === 'true') {
            showNotification('success', wpCloudflareR2Ajax.messages.settings_saved);
            localStorage.removeItem('r2_settings_updated');
        }
        
        // Check if we need to show access control notification from localStorage
        if (localStorage.getItem('r2_access_updated') === 'true') {
            showNotification('success', wpCloudflareR2Ajax.messages.access_saved);
            localStorage.removeItem('r2_access_updated');
        }
    }
    
    // Add CSS for spinning icon animation
    var style = document.createElement('style');
    style.innerHTML = `
        .spinning {
            animation: r2-spin 2s infinite linear;
            display: inline-block;
        }
        @keyframes r2-spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .r2-download-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 80px;
            min-height: 30px;
            position: relative;
            line-height: normal;
        }
        .r2-download-button .dashicons {
            margin: 0;
            font-size: 20px;
            line-height: 1;
            width: 20px;
            height: 20px;
            color: #0073aa;
            vertical-align: middle;
            position: relative;
            top: -2px;
        }
    `;
    document.head.appendChild(style);
});
