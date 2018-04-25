<?php namespace GlobalTechnology\CentralAuthenticationService; ?>

<?php
if ( isset( $_GET['update'] ) ) {
  $messages = array();
  switch ( $_GET['update'] ) {
    case "userpending":
      $messages[] = __( 'Invitation email sent to user. A confirmation link must be clicked for them to be added to your site.' );
      break;
    case "useradded":
      $messages[] = __( 'User has been added to your site.' );
      break;
  }
}

if ( isset( $_GET['error'] ) ) {
  $errors[] = __( 'Error adding user to Site' );
}
?>

<div class="wrap">
  <?php screen_icon(); ?>
    <h2 id="add-new-user"><?php _e( 'Add User', TEXT_DOMAIN ); ?></h2>

  <?php if ( isset( $errors ) ) : ?>
      <div class="error">
          <ul>
            <?php
            foreach ( $errors as $err ) {
              echo "<li>$err</li>\n";
            }
            ?>
          </ul>
      </div>
  <?php endif;

  if ( ! empty( $messages ) ) {
    foreach ( $messages as $msg ) {
      echo '<div id="message" class="updated"><p>' . $msg . '</p></div>';
    }
  } ?>

    <p><?php _e( 'Add users to your site.', TEXT_DOMAIN ); ?></p>
    <form action="" method="post" name="createuser" id="createuser" class="validate">
        <input name="action" type="hidden" value="createuser"/>
      <?php wp_nonce_field( 'create-user', '_wpnonce_create-user' ) ?>
      <?php
      foreach ( array( 'email' => 'email', 'role' => 'role' ) as $post_field => $var ) {
        $var = "new_user_$var";
        if ( isset( $_POST['createuser'] ) ) {
          if ( ! isset( $$var ) ) {
            $$var = isset( $_POST[ $post_field ] ) ? stripslashes( $_POST[ $post_field ] ) : '';
          }
        } else {
          $$var = false;
        }
      }
      ?>
        <table class="form-table">
            <tr class="form-field form-required">
                <th scope="row"><label for="email"><?php _e( 'E-mail', TEXT_DOMAIN ); ?> <span
                                class="description"><?php _e( '(required)', TEXT_DOMAIN ); ?></span></label></th>
                <td><input name="email" type="text" id="email" value="<?php echo esc_attr( $new_user_email ); ?>"/></td>
            </tr>
            <tr class="form-field">
                <th scope="row"><label for="role"><?php _e( 'Role', TEXT_DOMAIN ); ?></label></th>
                <td><select name="role" id="role">
                    <?php
                    if ( ! $new_user_role ) {
                      $new_user_role = get_option( 'default_role' );
                    }
                    wp_dropdown_roles( $new_user_role );
                    ?>
                    </select>
                </td>
            </tr>
        </table>
      <?php submit_button( __( 'Add User ', TEXT_DOMAIN ), 'primary', 'createuser', true, array( 'id' => 'createusersub' ) ); ?>
    </form>
</div>
