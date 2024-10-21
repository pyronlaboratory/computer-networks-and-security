try:
    import _hashlib as _hashopenssl
except ImportError:
    _hashopenssl = None
    _openssl_md_meths = None
else:
    _openssl_md_meths = frozenset(_hashopenssl.openssl_md_meth_names)

import hashlib as _hashlib
import warnings as _warnings

from _operator import _compare_digest as compare_digest


trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))


digest_size = None


class HMAC:
   
    """
    Implements the Keyed-Hash Message Authentication Code (HMAC) algorithm. It
    takes a key and a message, and uses a cryptographic hash function to generate
    a message authentication code (MAC).

    Attributes:
        blocksize (int): Initialized with a value of 64. It represents the block
            size used for padding the key.
        digest_cons (Callable[[bytes],_hashlibnew|digestmod]): Initialized in the
            `__init__` method to either a digest object or a lambda function
            creating a digest object based on the digestmod parameter.
        outer (_hashlibnewobject|None): Initialized in the `__init__` method to
            an instance of the digest algorithm specified by `digestmod`, which
            is used for the outer hash operation of the HMAC algorithm.
        inner (HashAlgorithm): Used in the inner hash calculation of the HMAC
            algorithm. It is created in the `__init__` method and its digest size
            is used to determine the block size of the HMAC algorithm.
        digest_size (int): Initialized with the value of `self.inner.digest_size`.
        block_size (int|None): Initialized to 64. It represents the block size
            used for hash operations, but if the hash object has a `block_size`
            attribute, it is used instead.
        update (Callable[[bytes],None]): Used to append more data to the message
            being hashed, effectively updating the HMAC object.

    """
    blocksize = 64  # 512-bit HMAC; can be changed in subclasses.

    def __init__(self, key, msg = None, digestmod = None):
        
        """
        Initializes an HMAC object, performing the following tasks:
        - Verifies the key and digestmod inputs, raising errors if invalid.
        - Creates two digest objects, `outer` and `inner`, based on the digestmod.
        - Determines the block size, using a default if not specified.
        - Truncates or pads the key to the block size.
        - Updates the `outer` and `inner` digest objects with the key.

        Args:
            key (bytes | bytearray): Required for initializing the object. It is
                expected to be a bytes or bytearray object, and its length is
                checked against the block size of the hash function.
            msg (bytes | str): Optional, with a default value of None. It represents
                the message to be processed by the hash object.
            digestmod (Callable or str or DigestModType): Required to initialize
                the hash object.

        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key: expected bytes or bytearray, but got %r" % type(key).__name__)

        if digestmod is None:
            raise ValueError('`digestmod` is required.')

        if callable(digestmod):
            self.digest_cons = digestmod
        elif isinstance(digestmod, str):
            self.digest_cons = lambda d=b'': _hashlib.new(digestmod, d)
        else:
            self.digest_cons = lambda d=b'': digestmod.new(d)


        self.outer = self.digest_cons()
        self.inner = self.digest_cons()
        self.digest_size = self.inner.digest_size


        if hasattr(self.inner, 'block_size'):
            blocksize = self.inner.block_size
            if blocksize < 16:
                _warnings.warn('block_size of %d seems too small; using our '
                               'default of %d.' % (blocksize, self.blocksize),
                               RuntimeWarning, 2)
                blocksize = self.blocksize
        else:
            _warnings.warn('No block_size attribute on given digest object; '
                           'Assuming %d.' % (self.blocksize),
                           RuntimeWarning, 2)
            blocksize = self.blocksize

        self.block_size = blocksize

        if len(key) > blocksize:
            key = self.digest_cons(key).digest()

        key = key.ljust(blocksize, b'\0')
        
        self.outer.update(key.translate(trans_5C))
        self.inner.update(key.translate(trans_36))
        
        if msg is not None:
            self.update(msg)

    @property
    def name(self):
        """
        Constructs a string representing the name of an HMAC object, combining the
        prefix "hmac-" with the name of its inner hash object.

        Returns:
            str: Concatenation of string "hmac-" with the result of calling
            `self.inner.name`, where `self.inner` is an object of a class, presumably
            containing a method `name`.

        """
        return "hmac-" + self.inner.name

    def update(self, msg):
        
        """
        Updates the inner hash object with the provided message data.

        Args:
            msg (Any): Used to pass a message to the `update` function, which is
                then passed to the `inner` object's `update` method.

        """
        self.inner.update(msg)

    def copy(self):
        """
        Creates a deep copy of the HMAC object, duplicating its properties and
        internal state, including the inner and outer hash objects and their digest
        sizes and values.

        Returns:
            self__class____new__self__class__: An instance of the same class as
            the original object, containing copies of the original object's attributes.

        """
        other = self.__class__.__new__(self.__class__)
        other.digest_cons = self.digest_cons
        other.digest_size = self.digest_size
        other.inner = self.inner.copy()
        other.outer = self.outer.copy()
        return other

    def _current(self):
        """
        Updates the outer hash object with the inner hash digest, returning the
        updated outer hash object.

        """
        h = self.outer.copy()
        h.update(self.inner.digest())
        return h

    def digest(self):
        """
        Returns the digest of the current HMAC object, which is the result of
        hashing the message using the HMAC algorithm.

        Returns:
            bytes: The digest of the hash object `h`.

        """
        h = self._current()
        return h.digest()

    def hexdigest(self):
        """
        Returns the hexadecimal representation of the hash digest of the HMAC object.

        Returns:
            str: The hexadecimal representation of the hash value generated by the
            hash object.

        """
        h = self._current()
        return h.hexdigest()

def new(key, msg = None, digestmod = None):
    return HMAC(key, msg, digestmod)


def digest(key, msg, digest):
    """
    Implements a custom HMAC (Keyed-Hash Message Authentication Code) algorithm,
    allowing for various digest algorithms and key sizes. It extends the standard
    HMAC algorithm with a custom key padding and translation mechanism.

    Args:
        key (bytes): Used to generate a fixed-size key for the HMAC algorithm. It
            may be provided as input or generated from a longer key.
        msg (bytes): The message to be digested, or more specifically, the data
            to be hashed and encrypted using a message digest algorithm.
        digest (str | Callable[[bytes], HashObject]): Used to specify either an
            OpenSSL digest method name or a callable that returns a hash object.

    Returns:
        bytes: The digest of the message `msg` after being processed through a
        two-layer HMAC (Keyed-Hashing for Message Authentication) mechanism using
        the provided key and digest algorithm.

    """
    if (_hashopenssl is not None and
            isinstance(digest, str) and digest in _openssl_md_meths):
        return _hashopenssl.hmac_digest(key, msg, digest)

    if callable(digest):
        digest_cons = digest
    elif isinstance(digest, str):
        digest_cons = lambda d=b'': _hashlib.new(digest, d)
    else:
        digest_cons = lambda d=b'': digest.new(d)

    inner = digest_cons()
    outer = digest_cons()
    
    blocksize = getattr(inner, 'block_size', 64)
    
    if len(key) > blocksize:
        key = digest_cons(key).digest()

    key = key + b'\x00' * (blocksize - len(key))

    inner.update(key.translate(trans_36))
    outer.update(key.translate(trans_5C))

    inner.update(msg)
    outer.update(inner.digest())

    return outer.digest()
