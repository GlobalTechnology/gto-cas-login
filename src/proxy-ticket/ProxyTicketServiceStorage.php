<?php namespace GlobalTechnology\CentralAuthenticationService {

  use Httpful\Mime;
  use Httpful\Request;

  class ProxyTicketServiceStorage extends \CAS_PGTStorage_AbstractStorage {

    function getStorageType() {
      return 'pgtservice';
    }

    function getStorageInfo() {
      return 'pgtservice';
    }

    function read( $pgt_iou ) {
      $response = Request::post(
        getenv( 'PGTSERVICE_ENDPOINT' ),
        array(
          'Username' => getenv( 'PGTSERVICE_USERNAME' ),
          'Password' => getenv( 'PGTSERVICE_PASSWORD' ),
          'PGTIOU'   => $pgt_iou,
        ), Mime::FORM )
                         ->addHeader( 'Content-Type', 'application/x-www-form-urlencoded' )
                         ->send();
      $dom      = new \DOMDocument();
      $dom->loadXML( $response->raw_body );

      return $dom->documentElement->textContent;
    }
  }
}
