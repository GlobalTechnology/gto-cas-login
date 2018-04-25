<?php namespace GlobalTechnology\CentralAuthenticationService {

  class RedisTicketStorage extends \CAS_PGTStorage_AbstractStorage {

    /**
     * @type \Redis
     */
    private $_redis;

    public function __construct( $cas_parent, $redis ) {
      parent::__construct( $cas_parent );
      $this->_redis = $redis;
    }

    function getStorageType() {
      return 'redis';
    }

    function getStorageInfo() {
      return 'redis';
    }

    function write( $pgt, $pgt_iou ) {
      $this->_redis->setex( $pgt_iou, 600, $pgt );
    }

    function read( $pgt_iou ) {
      $pgt = $this->_redis->get( $pgt_iou );
      if ( false !== $pgt ) {
        $this->_redis->delete( $pgt_iou );
      }

      return $pgt;
    }
  }
}
