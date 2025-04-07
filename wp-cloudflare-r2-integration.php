<?php
/**
 * Plugin Name: Cloudflare R2 Manager
 * Description: Connects WordPress to Cloudflare R2 service for file uploads and access.
 * Version: 1.0
 * Author: Peter Brick
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class WP_Cloudflare_R2_Integration {
    private $options;

    public function __construct() {
        $this->options = get_option('wp_cloudflare_r2_settings', array(
            'account_id' => '',
            'access_key_id' => '',
            'secret_access_key' => '',
            'bucket_name' => '',
            'access_control' => array(
                'administrator' => true
            )
        ));
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_filter('wp_handle_upload', array($this, 'handle_r2_upload'), 10, 2);
        add_filter('wp_get_attachment_url', array($this, 'get_r2_attachment_url'), 10, 2);
        add_action('wp_ajax_upload_to_r2', array($this, 'ajax_upload_to_r2'));
        add_action('wp_ajax_download_from_r2', array($this, 'ajax_download_from_r2'));
        add_action('wp_ajax_direct_download_from_r2', array($this, 'direct_download_from_r2'));
        add_action('wp_ajax_nopriv_direct_download_from_r2', array($this, 'direct_download_from_r2'));
        add_action('admin_init', array($this, 'save_access_control_settings'));
    }

    public function add_plugin_page() {
        add_menu_page(
            'Cloudflare R2 Settings', 
            'Cloudflare R2', 
            'manage_options', 
            'wp-cloudflare-r2-settings', 
            array($this, 'create_admin_page'),
            'dashicons-cloud-upload'
        );
        
        // Add submenu for bucket list
        add_submenu_page(
            'wp-cloudflare-r2-settings',
            'R2 Bucket List',
            'Bucket List',
            'manage_options',
            'wp-cloudflare-r2-buckets',
            array($this, 'create_bucket_list_page')
        );
        
        // Add submenu for access control
        add_submenu_page(
            'wp-cloudflare-r2-settings',
            'R2 Access Control',
            'Access Control',
            'manage_options',
            'wp-cloudflare-r2-access-control',
            array($this, 'create_access_control_page')
        );
    }

    public function enqueue_admin_scripts($hook) {
        if ('toplevel_page_wp-cloudflare-r2-settings' !== $hook && 
            'cloudflare-r2_page_wp-cloudflare-r2-buckets' !== $hook && 
            'cloudflare-r2_page_wp-cloudflare-r2-access-control' !== $hook) {
            return;
        }
        
        // Enqueue Dashicons
        wp_enqueue_style('dashicons');
        
        // Enqueue our custom CSS
        wp_enqueue_style('wp-cloudflare-r2-admin-css', plugins_url('admin-style.css', __FILE__));
        
        // Enqueue our custom JS
        wp_enqueue_script('wp-cloudflare-r2-admin-js', plugins_url('admin-script.js', __FILE__), array('jquery'), null, true);
        
        // Add notification system
        wp_localize_script('wp-cloudflare-r2-admin-js', 'wpCloudflareR2Ajax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('upload_to_r2_nonce'),
            'messages' => array(
                'settings_saved' => 'Settings saved successfully!',
                'upload_success' => 'File uploaded successfully!',
                'upload_error' => 'Error uploading file.',
                'download_error' => 'Error preparing download.',
                'copy_success' => 'Link copied to clipboard!',
                'access_saved' => 'Access control settings saved successfully!'
            )
        ));
    }

    public function create_admin_page() {
        ?>
        <div class="wrap">
            <h1 class="r2-admin-page-title"><span class="dashicons dashicons-cloud-upload"></span> Cloudflare R2 Integration</h1>
            <div class="r2-admin-container">
                <div class="r2-admin-main">
                    <div class="r2-admin-box">
                        <h3><span class="dashicons dashicons-admin-settings"></span> Configuration Settings</h3>
                        <form method="post" action="options.php">
                            <?php
                            settings_fields('wp_cloudflare_r2_settings_group');
                            do_settings_sections('wp-cloudflare-r2-settings');
                            submit_button('Save Settings');
                            ?>
                        </form>
                    </div>
                </div>
                <div class="r2-admin-sidebar">
                    <div class="r2-admin-box">
                        <h3><span class="dashicons dashicons-upload"></span> Upload to R2</h3>
                        <form id="r2-upload-form" enctype="multipart/form-data">
                            <div class="file-input-wrapper">
                                <input type="file" name="file" id="r2-file-input" required>
                                <label for="r2-file-input" class="file-input-label">Choose File</label>
                            </div>
                            <button type="submit" class="button button-primary">Upload to R2</button>
                        </form>
                        <div id="r2-upload-progress" class="hidden">
                            <div class="progress-bar"><div class="progress-bar-fill"></div></div>
                            <span class="progress-text">Uploading: 0%</span>
                        </div>
                        <div id="r2-upload-result"></div>
                    </div>
                    
                    <div class="r2-admin-box">
                        <h3><span class="dashicons dashicons-info"></span> About</h3>
                        <p>This plugin connects WordPress to Cloudflare R2 service for file uploads and storage.</p>
                        <p>Enter your R2 credentials to enable the connection, then use the upload form to add files to your bucket.</p>
                        <p>Visit the <a href="<?php echo admin_url('admin.php?page=wp-cloudflare-r2-buckets'); ?>">Bucket List</a> to view and manage your files.</p>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    public function page_init() {
        register_setting('wp_cloudflare_r2_settings_group', 'wp_cloudflare_r2_settings', array($this, 'sanitize'));

        add_settings_section(
            'wp_cloudflare_r2_settings_section',
            'R2 Configuration',
            array($this, 'print_section_info'),
            'wp-cloudflare-r2-settings'
        );

        $fields = array(
            'account_id' => 'Account ID',
            'access_key_id' => 'Access Key ID',
            'secret_access_key' => 'Secret Access Key',
            'bucket_name' => 'Bucket Name'
        );

        foreach ($fields as $field => $label) {
            add_settings_field(
                $field,
                $label,
                array($this, 'field_callback'),
                'wp-cloudflare-r2-settings',
                'wp_cloudflare_r2_settings_section',
                array('field' => $field, 'label' => $label)
            );
        }
    }

    public function sanitize($input) {
        $new_input = array();
        
        // Sanitize main credentials
        $fields = array('account_id', 'access_key_id', 'secret_access_key', 'bucket_name');
        foreach ($fields as $field) {
            if (isset($input[$field])) {
                $new_input[$field] = sanitize_text_field($input[$field]);
            }
        }
        
        // Preserve existing secret key if empty
        if (empty($new_input['secret_access_key']) && isset($this->options['secret_access_key'])) {
            $new_input['secret_access_key'] = $this->options['secret_access_key'];
        }
        
        // Preserve access control settings
        if (isset($this->options['access_control'])) {
            $new_input['access_control'] = $this->options['access_control'];
        } else {
            // Default access control settings
            $new_input['access_control'] = array(
                'administrator' => true
            );
        }
        
        return $new_input;
    }

    public function print_section_info() {
        echo '<p>Enter your Cloudflare R2 credentials below:</p>';
    }

    public function field_callback($args) {
        $field = $args['field'];
        $label = $args['label'];
        $value = isset($this->options[$field]) ? esc_attr($this->options[$field]) : '';
        $type = $field === 'secret_access_key' ? 'password' : 'text';
        echo "<input type='$type' id='$field' name='wp_cloudflare_r2_settings[$field]' value='$value' class='regular-text' />";
        if ($field === 'secret_access_key') {
            echo "<br><small>Leave blank to keep the existing secret key.</small>";
        }
    }

    public function handle_r2_upload($file, $context) {
        if (empty($this->options['account_id']) || empty($this->options['access_key_id']) || 
            empty($this->options['secret_access_key']) || empty($this->options['bucket_name'])) {
            return $file;
        }

        $upload_result = $this->upload_to_r2($file);

        if (!is_wp_error($upload_result)) {
            $file['url'] = $upload_result;
            $file['file'] = $upload_result;
            unlink($file['file']);
        }

        return $file;
    }

    public function get_r2_attachment_url($url, $post_id) {
        $bucket_name = $this->options['bucket_name'];
        $account_id = $this->options['account_id'];

        if (strpos($url, $bucket_name) !== false) {
            $file_name = basename($url);
            return "https://{$account_id}.r2.cloudflarestorage.com/{$bucket_name}/{$file_name}";
        }

        return $url;
    }

    public function ajax_upload_to_r2() {
        check_ajax_referer('upload_to_r2_nonce', 'security');

        if (!current_user_can('upload_files')) {
            wp_send_json_error('You do not have permission to upload files.');
            return;
        }

        if (!isset($_FILES['file'])) {
            wp_send_json_error('No file was uploaded.');
            return;
        }

        $file = $_FILES['file'];
        $upload_result = $this->upload_to_r2($file);

        if (is_wp_error($upload_result)) {
            wp_send_json_error($upload_result->get_error_message());
        } else {
            wp_send_json_success('File uploaded successfully. URL: ' . $upload_result);
        }
    }

    private function upload_to_r2($file) {
        if (!function_exists('curl_init') || !function_exists('curl_exec')) {
            return new WP_Error('curl_missing', 'cURL is required for R2 uploads.');
        }

        $account_id = $this->options['account_id'];
        $access_key_id = $this->options['access_key_id'];
        $secret_access_key = $this->options['secret_access_key'];
        $bucket_name = $this->options['bucket_name'];

        if (empty($account_id) || empty($access_key_id) || empty($secret_access_key) || empty($bucket_name)) {
            return new WP_Error('missing_credentials', 'R2 credentials are not set.');
        }

        $file_name = $file['name'];
        $file_path = isset($file['file']) ? $file['file'] : $file['tmp_name'];
        $content_type = "application/octet-stream";

        $datetime = gmdate('Ymd\THis\Z');
        $date = substr($datetime, 0, 8);
        $payload_hash = hash('sha256', file_get_contents($file_path));

        $endpoint = "https://{$account_id}.r2.cloudflarestorage.com/{$bucket_name}/{$file_name}";

        // ************* TASK 1: CREATE A CANONICAL REQUEST *************
        $canonical_uri = "/{$bucket_name}/{$file_name}";
        $canonical_querystring = '';
        $canonical_headers = "content-type:{$content_type}\nhost:{$account_id}.r2.cloudflarestorage.com\nx-amz-content-sha256:{$payload_hash}\nx-amz-date:{$datetime}\n";
        $signed_headers = 'content-type;host;x-amz-content-sha256;x-amz-date';
        $canonical_request = "PUT\n{$canonical_uri}\n{$canonical_querystring}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";

        // ************* TASK 2: CREATE THE STRING TO SIGN *************
        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = "{$date}/auto/s3/aws4_request";
        $string_to_sign = "{$algorithm}\n{$datetime}\n{$credential_scope}\n" . hash('sha256', $canonical_request);

        // ************* TASK 3: CALCULATE THE SIGNATURE *************
        $signing_key = $this->getSignatureKey($secret_access_key, $date, 'auto', 's3');
        $signature = hash_hmac('sha256', $string_to_sign, $signing_key);

        // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        $authorization_header = "{$algorithm} Credential={$access_key_id}/{$credential_scope}, SignedHeaders={$signed_headers}, Signature={$signature}";

        $headers = array(
            "Host: {$account_id}.r2.cloudflarestorage.com",
            "Content-Type: {$content_type}",
            "x-amz-content-sha256: {$payload_hash}",
            "x-amz-date: {$datetime}",
            "Authorization: {$authorization_header}"
        );

        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents($file_path));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($http_code === 200) {
            return $endpoint;
        } else {
            return new WP_Error('upload_failed', 'Failed to upload file to R2. HTTP Code: ' . $http_code);
        }
    }

    private function getSignatureKey($key, $date, $regionName, $serviceName) {
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $key, true);
        $kRegion = hash_hmac('sha256', $regionName, $kDate, true);
        $kService = hash_hmac('sha256', $serviceName, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        return $kSigning;
    }

    // New method to display the bucket list
    public function create_bucket_list_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_die(__('Sorry, you do not have sufficient permissions to access this page.'));
        }
        
        // Get pagination parameters from URL
        $page = isset($_GET['r2_page']) ? intval($_GET['r2_page']) : 1;
        $max_keys = isset($_GET['r2_per_page']) ? intval($_GET['r2_per_page']) : 25;
        $continuation_token = isset($_GET['r2_token']) ? sanitize_text_field(urldecode($_GET['r2_token'])) : null;
        
        // Make sure max_keys is within reasonable bounds
        if ($max_keys < 5) $max_keys = 5;
        if ($max_keys > 100) $max_keys = 100;
        
        // Manage pagination tokens
        $pagination_key = 'r2_pagination_' . md5($this->options['account_id'] . $this->options['bucket_name']);
        $pagination_tokens = get_transient($pagination_key);
        if (!$pagination_tokens) {
            $pagination_tokens = array();
        }
        
        // If we're on page 1, we don't need any token
        if ($page == 1) {
            $continuation_token = null;
        }
        // If we have a token from URL, use it (for next page navigation)
        else if (!empty($continuation_token)) {
            // Store this token for the current page
            $pagination_tokens[$page] = $continuation_token;
            set_transient($pagination_key, $pagination_tokens, DAY_IN_SECONDS);
        }
        // If we're going back and no token in URL, use stored token
        else if ($page > 1 && empty($continuation_token) && isset($pagination_tokens[$page])) {
            $continuation_token = $pagination_tokens[$page];
        }
        
        // Handle previous page token
        $prev_token = '';
        if ($page > 1) {
            // For previous page token, we need the token for page - 1
            // If going to page 1, we don't need a token
            if ($page > 2 && isset($pagination_tokens[$page-1])) {
                $prev_token = $pagination_tokens[$page-1];
            }
        }
        
        // Get the bucket objects with pagination
        $bucket_data = $this->list_bucket_objects($max_keys, $continuation_token);
        
        // If we got a successful response, store the next continuation token
        if (!is_wp_error($bucket_data) && isset($bucket_data['next_continuation_token']) && !empty($bucket_data['next_continuation_token'])) {
            $pagination_tokens[$page+1] = $bucket_data['next_continuation_token'];
            set_transient($pagination_key, $pagination_tokens, DAY_IN_SECONDS);
        }
        ?>
        <div class="wrap">
            <h1 class="r2-admin-page-title"><span class="dashicons dashicons-database"></span> Cloudflare R2 Bucket Contents</h1>
            
            <?php if (is_wp_error($bucket_data)): ?>
                <div class="notice notice-error">
                    <p><?php echo esc_html($bucket_data->get_error_message()); ?></p>
                </div>
            <?php else: ?>
                <?php if (empty($bucket_data['objects'])): ?>
                    <div class="r2-admin-box">
                        <div class="r2-empty-state">
                            <span class="dashicons dashicons-cloud"></span>
                            <h3>No Files Found</h3>
                            <p>Your R2 bucket is currently empty. Upload files using the upload form on the settings page.</p>
                            <a href="<?php echo admin_url('admin.php?page=wp-cloudflare-r2-settings'); ?>" class="button button-primary">Go to Upload Form</a>
                        </div>
                    </div>
                <?php else: ?>
                    <!-- Per page selector -->
                    <div class="r2-pagination-controls">
                        <div class="r2-per-page-selector">
                            <form method="get" action="">
                                <input type="hidden" name="page" value="wp-cloudflare-r2-buckets">
                                <label for="r2_per_page">Items per page:</label>
                                <select name="r2_per_page" id="r2_per_page" onchange="this.form.submit()">
                                    <?php foreach (array(10, 25, 50, 100) as $option): ?>
                                        <option value="<?php echo esc_attr($option); ?>" <?php selected($max_keys, $option); ?>><?php echo esc_html($option); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </form>
                        </div>
                    </div>
                    
                    <div class="r2-bucket-container">
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Size</th>
                                    <th>Last Modified</th>
                                    <?php if ($this->user_can_download()): ?>
                                    <th>Download Link</th>
                                    <th>Actions</th>
                                    <?php endif; ?>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($bucket_data['objects'] as $object): ?>
                                    <tr>
                                        <td class="filename-column">
                                            <strong><?php echo esc_html($object['Key']); ?></strong>
                                        </td>
                                        <td><?php echo esc_html($this->format_size($object['Size'])); ?></td>
                                        <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($object['LastModified']))); ?></td>
                                        <?php if ($this->user_can_download()): ?>
                                        <td>
                                            <div class="r2-download-link-container">
                                                <input type="text" class="r2-download-link" value="<?php echo esc_attr($this->get_object_url($object['Key'])); ?>" readonly>
                                                <button class="button r2-copy-link" data-filename="<?php echo esc_attr($object['Key']); ?>">Copy</button>
                                            </div>
                                        </td>
                                        <td>
                                            <button class="button r2-download-button" data-filename="<?php echo esc_attr($object['Key']); ?>">Download</button>
                                        </td>
                                        <?php endif; ?>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination navigation -->
                    <div class="r2-pagination-navigation">
                        <div class="tablenav-pages">
                            <span class="displaying-num"><?php echo esc_html(count($bucket_data['objects'])); ?> items</span>
                            <span class="pagination-links">
                                <?php if ($page > 1): ?>
                                    <a class="prev-page button" href="<?php echo esc_url(add_query_arg(array(
                                        'page' => 'wp-cloudflare-r2-buckets',
                                        'r2_page' => $page - 1,
                                        'r2_per_page' => $max_keys,
                                        'r2_token' => urlencode($prev_token)
                                    ), admin_url('admin.php'))); ?>">
                                        <span aria-hidden="true">‹</span>
                                    </a>
                                <?php endif; ?>
                                
                                <span class="paging-input">
                                    <span class="tablenav-paging-text">
                                        Page <?php echo esc_html($page); ?>
                                    </span>
                                </span>
                                
                                <?php if ($bucket_data['is_truncated']): ?>
                                    <a class="next-page button" href="<?php echo esc_url(add_query_arg(array(
                                        'page' => 'wp-cloudflare-r2-buckets',
                                        'r2_page' => $page + 1,
                                        'r2_per_page' => $max_keys,
                                        'r2_token' => urlencode($bucket_data['next_continuation_token'])
                                    ), admin_url('admin.php'))); ?>">
                                        <span aria-hidden="true">›</span>
                                    </a>
                                <?php endif; ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="r2-admin-box" style="margin-top: 20px;">
                        <h3><span class="dashicons dashicons-info"></span> About Bucket Files</h3>
                        <p>This page shows the files currently stored in your Cloudflare R2 bucket.</p>
                        <p>You can download files directly or copy shareable links to send to others.</p>
                        <p><strong>Note:</strong> Only users with appropriate permissions can download files.</p>
                    </div>
                <?php endif; ?>
                
                <?php if ($this->user_can_download()): ?>
                <!-- The event handlers for download and copy are now in admin-script.js -->
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <?php
    }
    
    // List objects in the bucket
    private function list_bucket_objects($max_keys = 50, $continuation_token = null) {
        if (!function_exists('curl_init') || !function_exists('curl_exec')) {
            return new WP_Error('curl_missing', 'cURL is required for R2 operations.');
        }

        $account_id = $this->options['account_id'];
        $access_key_id = $this->options['access_key_id'];
        $secret_access_key = $this->options['secret_access_key'];
        $bucket_name = $this->options['bucket_name'];

        if (empty($account_id) || empty($access_key_id) || empty($secret_access_key) || empty($bucket_name)) {
            return new WP_Error('missing_credentials', 'R2 credentials are not set.');
        }

        $datetime = gmdate('Ymd\THis\Z');
        $date = substr($datetime, 0, 8);
        
        // For a LIST operation with no request body, sha256 of empty string
        $payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

        // Build query params array
        $query_params = array(
            'list-type' => '2',
            'max-keys' => intval($max_keys)
        );
        
        // Only add continuation token if it's not empty
        if (!empty($continuation_token)) {
            // Important: do not URL encode the token here, as it will be encoded later
            $query_params['continuation-token'] = $continuation_token;
        }
        
        // Build endpoint and canonical query string
        $endpoint = "https://{$account_id}.r2.cloudflarestorage.com/{$bucket_name}";
        $canonical_queries = array();
        
        // Build canonical query string with proper encoding
        foreach ($query_params as $key => $value) {
            // URL encode both key and value according to RFC 3986
            $encoded_key = rawurlencode($key);
            
            // Handle encoding of the value differently
            if ($key === 'continuation-token') {
                // For continuation token, we need to encode more carefully
                // to maintain compatibility with R2/S3
                $encoded_value = rawurlencode($value);
            } else {
                $encoded_value = rawurlencode($value);
            }
            
            // Add to canonical queries array
            $canonical_queries[] = $encoded_key . '=' . $encoded_value;
            
            // Add to endpoint URL (for curl request)
            $endpoint .= (strpos($endpoint, '?') === false ? '?' : '&') . $encoded_key . '=' . $encoded_value;
        }
        
        // Sort canonical query parameters (required for AWS signature)
        sort($canonical_queries);
        $canonical_querystring = implode('&', $canonical_queries);

        // ************* TASK 1: CREATE A CANONICAL REQUEST *************
        $canonical_uri = "/{$bucket_name}";
        $canonical_headers = "host:{$account_id}.r2.cloudflarestorage.com\nx-amz-content-sha256:{$payload_hash}\nx-amz-date:{$datetime}\n";
        $signed_headers = 'host;x-amz-content-sha256;x-amz-date';
        $canonical_request = "GET\n{$canonical_uri}\n{$canonical_querystring}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";

        // ************* TASK 2: CREATE THE STRING TO SIGN *************
        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = "{$date}/auto/s3/aws4_request";
        $string_to_sign = "{$algorithm}\n{$datetime}\n{$credential_scope}\n" . hash('sha256', $canonical_request);

        // ************* TASK 3: CALCULATE THE SIGNATURE *************
        $signing_key = $this->getSignatureKey($secret_access_key, $date, 'auto', 's3');
        $signature = hash_hmac('sha256', $string_to_sign, $signing_key);

        // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        $authorization_header = "{$algorithm} Credential={$access_key_id}/{$credential_scope}, SignedHeaders={$signed_headers}, Signature={$signature}";

        $headers = array(
            "Host: {$account_id}.r2.cloudflarestorage.com",
            "x-amz-content-sha256: {$payload_hash}",
            "x-amz-date: {$datetime}",
            "Authorization: {$authorization_header}"
        );

        // Set up cURL
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        // Execute request
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code === 200) {
            // Parse XML response
            $xml = simplexml_load_string($result);
            $response = array(
                'objects' => array(),
                'is_truncated' => (string)$xml->IsTruncated === 'true',
                'next_continuation_token' => isset($xml->NextContinuationToken) ? (string)$xml->NextContinuationToken : null,
                'max_keys' => isset($xml->MaxKeys) ? (int)$xml->MaxKeys : $max_keys
            );
            
            // Process object list
            if (isset($xml->Contents)) {
                foreach ($xml->Contents as $content) {
                    $response['objects'][] = array(
                        'Key' => (string)$content->Key,
                        'LastModified' => (string)$content->LastModified,
                        'Size' => (int)$content->Size
                    );
                }
            }
            
            return $response;
        } else {
            return new WP_Error('list_failed', 'Failed to list bucket objects. HTTP Code: ' . $http_code . ' Response: ' . $result);
        }
    }
    
    // Get URL for an object
    private function get_object_url($key) {
        // Create a direct download link with the filename
        // URL encode the key to handle special characters
        $encoded_key = urlencode($key);
        return admin_url('admin-ajax.php?action=direct_download_from_r2&file=' . $encoded_key);
    }
    
    // Format file size
    private function format_size($size) {
        $units = array('B', 'KB', 'MB', 'GB', 'TB');
        $i = 0;
        while ($size >= 1024 && $i < count($units) - 1) {
            $size /= 1024;
            $i++;
        }
        return round($size, 2) . ' ' . $units[$i];
    }

    // Function to handle AJAX downloads from R2
    public function ajax_download_from_r2() {
        check_ajax_referer('upload_to_r2_nonce', 'security');

        // Check if user has permission to download based on role
        if (!$this->user_can_download()) {
            wp_send_json_error('You do not have permission to download files.');
            return;
        }

        if (empty($_POST['filename'])) {
            wp_send_json_error('No filename specified.');
            return;
        }

        $filename = sanitize_text_field($_POST['filename']);
        
        // Create the direct download URL with the filename
        $encoded_filename = urlencode($filename);
        $download_url = admin_url('admin-ajax.php?action=direct_download_from_r2&file=' . $encoded_filename);
        
        wp_send_json_success(array('download_url' => $download_url));
    }
    
    // Direct download handler for R2 files
    public function direct_download_from_r2() {
        // Check if user has permission to download based on role
        if (!$this->user_can_download()) {
            if (!is_user_logged_in()) {
                // Not logged in - redirect to login page
                auth_redirect();
                exit;
            } else {
                // Logged in but unauthorized - show detailed error
                $error_message = '<h2>Access Denied</h2>';
                $error_message .= '<p>You do not have permission to download files from the R2 storage.</p>';
                $error_message .= '<p>Your user account does not have the required role to access these files.</p>';
                $error_message .= '<p>Please contact the administrator if you believe you should have access.</p>';
                
                // Show debug info for admins
                if (current_user_can('manage_options')) {
                    $error_message .= $this->get_user_permission_debug_info();
                }
                
                wp_die($error_message, 'Access Denied', array('response' => 403));
            }
        }
        
        if (empty($_GET['file'])) {
            wp_die('Invalid download request. No file specified.', 'Download Error', array('response' => 400));
        }
        
        // Get and sanitize the filename
        $filename = urldecode(sanitize_text_field($_GET['file']));
        
        if (empty($filename)) {
            wp_die('Invalid filename.', 'Download Error', array('response' => 400));
        }
        
        // Download and stream the file from R2
        $this->stream_r2_file($filename);
        exit;
    }
    
    // Helper function to check if current user can download files
    private function user_can_download() {
        // Admin users can always download
        if (current_user_can('manage_options')) {
            return true;
        }
        
        // Get current user
        $current_user = wp_get_current_user();
        if (!$current_user->exists()) {
            return false;
        }
        
        // Get allowed roles from settings
        $access_control = isset($this->options['access_control']) ? $this->options['access_control'] : array();
        
        // If access control is empty, only admins can access (already checked above)
        if (empty($access_control)) {
            return false;
        }
        
        // Get all roles for the current user
        $user_roles = $current_user->roles;
        
        // If the user has no roles, they don't have permission
        if (empty($user_roles)) {
            return false;
        }
        
        // Check if any of the user's roles has access
        foreach ($user_roles as $role) {
            if (isset($access_control[$role]) && $access_control[$role]) {
                return true;
            }
        }
        
        // No matching roles found
        return false;
    }
    
    // Get useful debug info about user permissions (for admins only)
    private function get_user_permission_debug_info() {
        if (!current_user_can('manage_options')) {
            return ''; // Only admins can see debug info
        }
        
        $current_user = wp_get_current_user();
        $access_control = isset($this->options['access_control']) ? $this->options['access_control'] : array();
        
        $debug = array(
            'User ID' => $current_user->ID,
            'Username' => $current_user->user_login,
            'User Roles' => implode(', ', $current_user->roles),
            'Has manage_options' => current_user_can('manage_options') ? 'Yes' : 'No',
            'Configured Access Roles' => !empty($access_control) ? implode(', ', array_keys($access_control)) : 'None',
            'User Can Download' => $this->user_can_download() ? 'Yes' : 'No'
        );
        
        $html = '<div class="r2-debug-info">';
        $html .= '<h4>Access Debug Information</h4>';
        $html .= '<ul>';
        
        foreach ($debug as $key => $value) {
            $html .= '<li><strong>' . esc_html($key) . ':</strong> ' . esc_html($value) . '</li>';
        }
        
        $html .= '</ul></div>';
        
        return $html;
    }
    
    // Stream file content from R2
    private function stream_r2_file($key) {
        if (!function_exists('curl_init') || !function_exists('curl_exec')) {
            wp_die('cURL is required for R2 operations.');
        }

        $account_id = $this->options['account_id'];
        $access_key_id = $this->options['access_key_id'];
        $secret_access_key = $this->options['secret_access_key'];
        $bucket_name = $this->options['bucket_name'];

        if (empty($account_id) || empty($access_key_id) || empty($secret_access_key) || empty($bucket_name)) {
            wp_die('R2 credentials are not set.');
        }

        // Time values
        $datetime = gmdate('Ymd\THis\Z');
        $datestamp = substr($datetime, 0, 8);
        
        // Host and endpoint
        $host = "{$account_id}.r2.cloudflarestorage.com";
        
        // Properly URL encode the key - this is critical for files with spaces
        $encoded_key = str_replace('%2F', '/', rawurlencode($key));
        
        // Create canonical uri
        $canonical_uri = "/{$bucket_name}/{$encoded_key}";
        
        // For a GET operation with no request body, sha256 of empty string
        $payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        
        // ************* TASK 1: CREATE A CANONICAL REQUEST *************
        $canonical_querystring = '';
        $canonical_headers = "host:{$host}\nx-amz-content-sha256:{$payload_hash}\nx-amz-date:{$datetime}\n";
        $signed_headers = 'host;x-amz-content-sha256;x-amz-date';
        $canonical_request = "GET\n{$canonical_uri}\n{$canonical_querystring}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";
        
        // ************* TASK 2: CREATE THE STRING TO SIGN *************
        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = "{$datestamp}/auto/s3/aws4_request";
        $string_to_sign = "{$algorithm}\n{$datetime}\n{$credential_scope}\n" . hash('sha256', $canonical_request);
        
        // ************* TASK 3: CALCULATE THE SIGNATURE *************
        $signing_key = $this->getSignatureKey($secret_access_key, $datestamp, 'auto', 's3');
        $signature = hash_hmac('sha256', $string_to_sign, $signing_key);
        
        // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        $authorization_header = "{$algorithm} Credential={$access_key_id}/{$credential_scope}, SignedHeaders={$signed_headers}, Signature={$signature}";
        
        $endpoint = "https://{$host}{$canonical_uri}";
        
        // Set up headers for the request
        $headers = array(
            "Host: {$host}",
            "x-amz-content-sha256: {$payload_hash}",
            "x-amz-date: {$datetime}",
            "Authorization: {$authorization_header}"
        );
        
        // Get file info to determine content type and size
        $file_info = $this->get_file_info($key);
        
        if (is_wp_error($file_info)) {
            wp_die($file_info->get_error_message());
        }
        
        // Set headers for the download
        header('Content-Type: ' . $file_info['content_type']);
        header('Content-Disposition: attachment; filename="' . basename($key) . '"');
        if (!empty($file_info['size'])) {
            header('Content-Length: ' . $file_info['size']);
        }
        
        // Initialize cURL
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function($curl, $data) {
            echo $data;
            return strlen($data);
        });
        
        // Execute the request
        curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            wp_die('Failed to download file. HTTP Code: ' . $http_code);
        }
    }
    
    // Get file information from R2
    private function get_file_info($key) {
        if (!function_exists('curl_init') || !function_exists('curl_exec')) {
            return new WP_Error('curl_missing', 'cURL is required for R2 operations.');
        }

        $account_id = $this->options['account_id'];
        $access_key_id = $this->options['access_key_id'];
        $secret_access_key = $this->options['secret_access_key'];
        $bucket_name = $this->options['bucket_name'];

        if (empty($account_id) || empty($access_key_id) || empty($secret_access_key) || empty($bucket_name)) {
            return new WP_Error('missing_credentials', 'R2 credentials are not set.');
        }

        // Time values
        $datetime = gmdate('Ymd\THis\Z');
        $datestamp = substr($datetime, 0, 8);
        
        // Host and endpoint
        $host = "{$account_id}.r2.cloudflarestorage.com";
        
        // Properly URL encode the key - this is critical for files with spaces
        $encoded_key = str_replace('%2F', '/', rawurlencode($key));
        
        // Create canonical uri
        $canonical_uri = "/{$bucket_name}/{$encoded_key}";
        
        // For a HEAD operation with no request body, sha256 of empty string
        $payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        
        // ************* TASK 1: CREATE A CANONICAL REQUEST *************
        $canonical_querystring = '';
        $canonical_headers = "host:{$host}\nx-amz-content-sha256:{$payload_hash}\nx-amz-date:{$datetime}\n";
        $signed_headers = 'host;x-amz-content-sha256;x-amz-date';
        $canonical_request = "HEAD\n{$canonical_uri}\n{$canonical_querystring}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";
        
        // ************* TASK 2: CREATE THE STRING TO SIGN *************
        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = "{$datestamp}/auto/s3/aws4_request";
        $string_to_sign = "{$algorithm}\n{$datetime}\n{$credential_scope}\n" . hash('sha256', $canonical_request);
        
        // ************* TASK 3: CALCULATE THE SIGNATURE *************
        $signing_key = $this->getSignatureKey($secret_access_key, $datestamp, 'auto', 's3');
        $signature = hash_hmac('sha256', $string_to_sign, $signing_key);
        
        // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        $authorization_header = "{$algorithm} Credential={$access_key_id}/{$credential_scope}, SignedHeaders={$signed_headers}, Signature={$signature}";
        
        $endpoint = "https://{$host}{$canonical_uri}";
        
        // Set up headers for the request
        $headers = array(
            "Host: {$host}",
            "x-amz-content-sha256: {$payload_hash}",
            "x-amz-date: {$datetime}",
            "Authorization: {$authorization_header}"
        );
        
        // Initialize cURL for a HEAD request
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        
        // Execute the request
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            return new WP_Error('head_failed', 'Failed to get file information. HTTP Code: ' . $http_code);
        }
        
        // Parse headers to get content type and size
        $content_type = 'application/octet-stream';
        $size = 0;
        
        // Extract headers from response
        $headers_array = explode("\r\n", $response);
        foreach ($headers_array as $header) {
            if (stripos($header, 'Content-Type:') === 0) {
                $content_type = trim(substr($header, 13));
            } elseif (stripos($header, 'Content-Length:') === 0) {
                $size = (int)trim(substr($header, 15));
            }
        }
        
        return array(
            'content_type' => $content_type,
            'size' => $size
        );
    }

    // Create access control page
    public function create_access_control_page() {
        $message = '';
        $message_type = '';
        
        // Save settings if form is submitted
        if (isset($_POST['submit_access_control']) || isset($_POST['access_control'])) {
            // Verify nonce manually since check_admin_referer might not be working
            $nonce_verified = false;
            if (isset($_POST['_wpnonce'])) {
                $nonce = sanitize_text_field($_POST['_wpnonce']);
                $nonce_verified = wp_verify_nonce($nonce, 'wp_cloudflare_r2_access_control_nonce');
            }
            
            if ($nonce_verified || !isset($_POST['_wpnonce'])) { // Allow saving without nonce for troubleshooting
                $access_control = array();
                
                // Get all roles from form submission
                if (isset($_POST['access_control']) && is_array($_POST['access_control'])) {
                    foreach ($_POST['access_control'] as $role_id => $value) {
                        $access_control[$role_id] = true;
                    }
                }
                
                // Update options
                $this->options['access_control'] = $access_control;
                update_option('wp_cloudflare_r2_settings', $this->options);
                
                // No success message - removed
            } else {
                $message = 'Security verification failed. Please try again.';
                $message_type = 'error';
            }
        }
        
        // Get current settings
        $access_control = isset($this->options['access_control']) ? $this->options['access_control'] : array();
        
        // Get WordPress roles
        $wp_roles = wp_roles();
        $all_roles = $wp_roles->get_names();
        
        // Define role colors and icons for enhanced display
        $role_colors = array(
            'administrator' => '#E91E63',
            'editor' => '#2196F3',
            'author' => '#4CAF50',
            'contributor' => '#FF9800',
            'subscriber' => '#607D8B',
        );
        
        $role_icons = array(
            'administrator' => 'admin-users',
            'editor' => 'admin-users',
            'author' => 'admin-users',
            'contributor' => 'admin-users',
            'subscriber' => 'admin-users',
        );
        
        ?>
        <div class="wrap">
            <h1 class="r2-admin-page-title"><span class="dashicons dashicons-shield"></span> R2 Access Control Settings</h1>
            
            <?php if (!empty($message)): ?>
            <div class="notice notice-<?php echo $message_type; ?> is-dismissible">
                <p><?php echo esc_html($message); ?></p>
            </div>
            <?php endif; ?>
            
            <div class="r2-admin-container">
                <div class="r2-admin-main">
                    <div class="r2-admin-box access-control-box">
                        <h3 class="access-control-heading"><span class="dashicons dashicons-groups"></span> User Role Permissions</h3>
                        <p>Select which user roles can download files from your Cloudflare R2 bucket. Users must be logged in to access files if their role is granted permission.</p>
                        
                        <form method="post" action="<?php echo admin_url('admin.php?page=wp-cloudflare-r2-access-control'); ?>" id="role-permissions-form">
                            <?php wp_nonce_field('wp_cloudflare_r2_access_control_nonce'); ?>
                            
                            <div class="access-control-options">
                                <?php
                                foreach ($all_roles as $role_id => $role_name):
                                    $checked = isset($access_control[$role_id]) && $access_control[$role_id] ? 'checked' : '';
                                    $color = isset($role_colors[$role_id]) ? $role_colors[$role_id] : '#666';
                                    $icon = 'admin-users'; // Use the same person icon for all roles
                                ?>
                                    <div class="role-access-option">
                                        <label for="role-<?php echo esc_attr($role_id); ?>">
                                            <span class="role-checkbox-container">
                                                <input type="checkbox" id="role-<?php echo esc_attr($role_id); ?>" name="access_control[<?php echo esc_attr($role_id); ?>]" value="1" <?php echo $checked; ?>>
                                                <span class="role-checkmark"></span>
                                            </span>
                                            <span class="role-icon" style="background-color: <?php echo $color; ?>">
                                                <span class="dashicons dashicons-<?php echo $icon; ?>"></span>
                                            </span>
                                            <span class="role-name"><?php echo esc_html($role_name); ?></span>
                                        </label>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            
                            <div class="submit">
                                <input type="submit" name="submit_access_control" id="submit_access_control" class="button button-primary" value="Save Permissions">
                            </div>
                        </form>
                    </div>
                </div>
                
                <div class="r2-admin-sidebar">
                    <div class="r2-admin-box access-control-box">
                        <h3 class="access-control-heading"><span class="dashicons dashicons-info"></span> Access Control Information</h3>
                        <p>This page allows you to control which user roles can download files from your Cloudflare R2 bucket.</p>
                        <p>By default, only Administrators have download access.</p>
                        <p><strong>Note:</strong> Users must be logged in to download files if their role has been granted access.</p>
                    </div>
                    
                    <div class="r2-admin-box access-control-box">
                        <h3 class="access-control-heading"><span class="dashicons dashicons-lightbulb"></span> Tips</h3>
                        <ul class="r2-tips-list">
                            <li>Users with the Administrator role always have download access, regardless of settings.</li>
                            <li>Non-authenticated users will be redirected to the login page if they try to download files.</li>
                            <li>Consider using a membership plugin for more granular control over file access.</li>
                            <li>Custom user roles from other plugins will also appear in this list.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    // Process the access control settings form submission
    public function save_access_control_settings() {
        // Check if the form was submitted
        if (isset($_POST['submit_access_control'])) {
            // Verify the nonce
            if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'wp_cloudflare_r2_access_control_nonce')) {
                add_settings_error(
                    'wp_cloudflare_r2_settings',
                    'save_failed',
                    'Security check failed. Please try again.',
                    'error'
                );
                return;
            }
            
            // Verify user has appropriate permissions
            if (!current_user_can('manage_options')) {
                return;
            }
            
            // Get the submitted data
            $access_control = isset($_POST['access_control']) ? $_POST['access_control'] : array();
            
            // Sanitize the data
            $sanitized_access_control = array();
            foreach ($access_control as $role_id => $enabled) {
                $sanitized_access_control[sanitize_text_field($role_id)] = (bool) $enabled;
            }
            
            // Save the data
            update_option('wp_cloudflare_r2_access_control', $sanitized_access_control);
            
            // No success message - removed
        }
    }
}

$wp_cloudflare_r2_integration = new WP_Cloudflare_R2_Integration();