<?php
/**
 * WordPress File Guard
 *
 * Simple file and directory protection for WordPress plugins.
 * Handles .htaccess rules, index files, and protection verification.
 *
 * @package ArrayPress\FileGuard
 * @since   1.0.0
 * @author  David Sherlock
 * @license GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace ArrayPress\FileGuard;

/**
 * Protector Class
 *
 * Manages file and directory protection for WordPress uploads.
 */
class Protector {

	/**
	 * Plugin prefix for the upload directory.
	 *
	 * @var string
	 */
	private string $prefix;

	/**
	 * Allowed file extensions for public access.
	 *
	 * @var array
	 */
	private array $allowed_extensions = [];

	/**
	 * Whether to use dated folders (year/month).
	 *
	 * @var bool
	 */
	private bool $use_dated_folders = true;

	/**
	 * Constructor.
	 *
	 * @param string $prefix             Plugin prefix for upload directory.
	 * @param array  $allowed_extensions File extensions allowed for public access.
	 * @param bool   $use_dated_folders  Whether to organize by year/month.
	 */
	public function __construct(
		string $prefix,
		array $allowed_extensions = [ 'jpg', 'jpeg', 'png', 'gif', 'webp' ],
		bool $use_dated_folders = true
	) {
		$this->prefix             = $prefix;
		$this->allowed_extensions = $allowed_extensions;
		$this->use_dated_folders  = $use_dated_folders;
	}

	/**
	 * Create all protection files in the upload directory.
	 *
	 * @param bool $force Force creation even if recently checked.
	 *
	 * @return bool True if successful.
	 */
	public function protect( bool $force = false ): bool {
		$transient_key = $this->prefix . '_protection_check';

		if ( ! $force && get_transient( $transient_key ) ) {
			return true;
		}

		$upload_path = $this->get_upload_path();

		if ( ! wp_is_writable( $upload_path ) ) {
			return false;
		}

		// Create directory if it doesn't exist
		wp_mkdir_p( $upload_path );

		// Create protection files
		$created = $this->create_protection_files( $upload_path );

		// Protect subdirectories if they exist
		if ( $this->use_dated_folders ) {
			$this->protect_subdirectories( $upload_path );
		}

		if ( $created ) {
			set_transient( $transient_key, true, DAY_IN_SECONDS );
		}

		return $created;
	}

	/**
	 * Create protection files in a directory.
	 *
	 * @param string $path Directory path.
	 *
	 * @return bool True if all files created successfully.
	 */
	private function create_protection_files( string $path ): bool {
		$files = [
			'index.php'  => '<?php // Silence is golden.',
			'index.html' => '',
			'.htaccess'  => $this->get_htaccess_rules()
		];

		$success = true;

		foreach ( $files as $filename => $content ) {
			$filepath = trailingslashit( $path ) . $filename;

			if ( ! file_exists( $filepath ) ) {
				$result = file_put_contents( $filepath, $content );
				if ( false === $result ) {
					$success = false;
				}
			}
		}

		return $success;
	}

	/**
	 * Protect all subdirectories.
	 *
	 * @param string $base_path Base upload path.
	 *
	 * @return void
	 */
	private function protect_subdirectories( string $base_path ): void {
		// Get all subdirectories (year/month folders)
		$pattern = trailingslashit( $base_path ) . '*/*';
		$subdirs = glob( $pattern, GLOB_ONLYDIR );

		if ( ! empty( $subdirs ) ) {
			foreach ( $subdirs as $dir ) {
				if ( wp_is_writable( $dir ) ) {
					$index_file = trailingslashit( $dir ) . 'index.php';
					if ( ! file_exists( $index_file ) ) {
						file_put_contents( $index_file, '<?php // Silence is golden.' );
					}
				}
			}
		}
	}

	/**
	 * Get .htaccess rules for Apache.
	 *
	 * @return string
	 */
	private function get_htaccess_rules(): string {
		$rules = "Options -Indexes\n";
		$rules .= "deny from all\n";

		// Allow specific file types if configured
		if ( ! empty( $this->allowed_extensions ) ) {
			$extensions = implode( '|', $this->allowed_extensions );
			$rules      .= "<FilesMatch '\.(" . $extensions . ")$'>\n";
			$rules      .= "    Order Allow,Deny\n";
			$rules      .= "    Allow from all\n";
			$rules      .= "</FilesMatch>\n";
		}

		return apply_filters( $this->prefix . '_htaccess_rules', $rules );
	}

	/**
	 * Get the upload directory path.
	 *
	 * @param bool $dated Whether to include year/month subdirectory.
	 *
	 * @return string
	 */
	public function get_upload_path( bool $dated = false ): string {
		$wp_upload_dir = wp_upload_dir();
		$path          = trailingslashit( $wp_upload_dir['basedir'] ) . $this->prefix;

		if ( $dated && $this->use_dated_folders ) {
			$time = current_time( 'mysql' );
			$y    = substr( $time, 0, 4 );
			$m    = substr( $time, 5, 2 );
			$path .= "/$y/$m";
		}

		return $path;
	}

	/**
	 * Get the upload directory URL.
	 *
	 * @param bool $dated Whether to include year/month subdirectory.
	 *
	 * @return string
	 */
	public function get_upload_url( bool $dated = false ): string {
		$wp_upload_dir = wp_upload_dir();
		$url           = trailingslashit( $wp_upload_dir['baseurl'] ) . $this->prefix;

		if ( $dated && $this->use_dated_folders ) {
			$time = current_time( 'mysql' );
			$y    = substr( $time, 0, 4 );
			$m    = substr( $time, 5, 2 );
			$url  .= "/$y/$m";
		}

		return $url;
	}

	/**
	 * Check if the upload directory is protected.
	 *
	 * @param bool $force Force recheck even if cached.
	 *
	 * @return bool
	 */
	public function is_protected( bool $force = false ): bool {
		$transient_key = $this->prefix . '_uploads_protected';

		if ( ! $force ) {
			$cached = get_transient( $transient_key );
			if ( false !== $cached ) {
				return (bool) $cached;
			}
		}

		$upload_path = $this->get_upload_path();
		$htaccess    = trailingslashit( $upload_path ) . '.htaccess';

		// Quick check - if no .htaccess, not protected
		if ( ! file_exists( $htaccess ) ) {
			set_transient( $transient_key, 0, HOUR_IN_SECONDS );

			return false;
		}

		// Test with a temporary file
		$test_file = $this->prefix . '-test-' . wp_generate_password( 8, false ) . '.txt';
		$test_path = trailingslashit( $upload_path ) . $test_file;

		// Create test file
		file_put_contents( $test_path, 'test' );

		// Try to access it
		$test_url = trailingslashit( $this->get_upload_url() ) . $test_file;
		$response = wp_remote_get( $test_url, [
			'timeout'     => 3,
			'sslverify'   => false,
			'redirection' => 0
		] );

		$code      = wp_remote_retrieve_response_code( $response );
		$protected = ( 200 !== $code );

		// Clean up
		@unlink( $test_path );

		// Cache result
		set_transient( $transient_key, $protected ? 1 : 0, 12 * HOUR_IN_SECONDS );

		return $protected;
	}

	/**
	 * Filter upload directory for specific post types.
	 *
	 * @param array $upload Upload directory array.
	 *
	 * @return array
	 */
	public function filter_upload_dir( array $upload ): array {
		if ( $this->use_dated_folders ) {
			$time   = current_time( 'mysql' );
			$y      = substr( $time, 0, 4 );
			$m      = substr( $time, 5, 2 );
			$subdir = "/{$this->prefix}/$y/$m";
		} else {
			$subdir = "/{$this->prefix}";
		}

		$upload['subdir'] = $subdir;
		$upload['path']   = $upload['basedir'] . $subdir;
		$upload['url']    = $upload['baseurl'] . $subdir;

		// Ensure directory exists
		wp_mkdir_p( $upload['path'] );

		return $upload;
	}

	/**
	 * Setup automatic upload directory filtering.
	 *
	 * @param callable|string|array $condition Condition to check:
	 *                                         - Callable: Custom function returning bool
	 *                                         - String/Array: Post type(s) to check
	 *                                         - 'admin:page_slug': Admin page check
	 *
	 * @return void
	 */
	public function setup_upload_filter( $condition ): void {
		add_filter( 'wp_handle_upload_prefilter', function ( $file ) use ( $condition ) {
			$should_filter = false;

			// Custom callable
			if ( is_callable( $condition ) ) {
				$should_filter = call_user_func( $condition );
			} // Admin page check (format: "admin:page_slug")
			elseif ( is_string( $condition ) && str_starts_with( $condition, 'admin:' ) ) {
				$page          = substr( $condition, 6 );
				$should_filter = is_admin() && isset( $_GET['page'] ) && $_GET['page'] === $page;
			} // Post type check
			elseif ( ! empty( $_REQUEST['post_id'] ) ) {
				$post_types    = (array) $condition;
				$post_type     = get_post_type( absint( $_REQUEST['post_id'] ) );
				$should_filter = in_array( $post_type, $post_types, true );
			}

			if ( $should_filter ) {
				add_filter( 'upload_dir', [ $this, 'filter_upload_dir' ] );
			}

			return $file;
		}, 5 );
	}

	/**
	 * Schedule automatic protection checks.
	 *
	 * @param string $hook WordPress admin hook to run on (default: admin_init).
	 *
	 * @return void
	 */
	public function schedule_protection( string $hook = 'admin_init' ): void {
		add_action( $hook, [ $this, 'protect' ] );
	}

	/**
	 * Get Nginx configuration rules.
	 *
	 * @return string
	 */
	public function get_nginx_rules(): string {
		$location = '/' . $this->prefix . '/';
		$rules    = "location ~ ^$location {\n";
		$rules    .= "    deny all;\n";

		if ( ! empty( $this->allowed_extensions ) ) {
			$extensions = implode( '|', $this->allowed_extensions );
			$rules      .= "    location ~ \\.($extensions)$ {\n";
			$rules      .= "        allow all;\n";
			$rules      .= "    }\n";
		}

		$rules .= "}\n";

		return apply_filters( $this->prefix . '_nginx_rules', $rules );
	}

	/**
	 * Delete all protection files.
	 *
	 * @return bool True if successful.
	 */
	public function unprotect(): bool {
		$upload_path = $this->get_upload_path();
		$files       = [ '.htaccess', 'index.php', 'index.html' ];
		$success     = true;

		foreach ( $files as $file ) {
			$filepath = trailingslashit( $upload_path ) . $file;
			if ( file_exists( $filepath ) ) {
				if ( ! @unlink( $filepath ) ) {
					$success = false;
				}
			}
		}

		// Clear transients
		delete_transient( $this->prefix . '_protection_check' );
		delete_transient( $this->prefix . '_uploads_protected' );

		return $success;
	}

}