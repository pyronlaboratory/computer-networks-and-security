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
    Generates an HMAC (Hash-based Message Authentication Code) based on a given
    key and message. It takes care of generating the inner and outer hashes,
    handling the block size, and returning the final digest.

    Attributes:
        blocksize (int): 64 by default, which represents the size of the block to
            be used when hashing the message. It can be changed through the
            constructor or property setters.
        digest_cons (instance): The lambda function that generates the digest of
            the input message when called.
        outer (instance): Used to store the result of updating a message using the
            underlying digest algorithm, such as SHA-256 or SHA-512.
        inner (instance): Used for hashing password. It is initialized with a
            digest object, which is used to hash the password.
        digest_size (int): 36 bits by default, indicating the size of the digest
            block used for hashing.
        block_size (int): 64 by default. It represents the size of the block used
            for the HMAC calculation.
        update (method): Used to update the inner digest with a given message.

    """
    blocksize = 64  # 512-bit HMAC; can be changed in subclasses.

    def __init__(self, key, msg = None, digestmod = None):
        
        """
        Of the HMAC class initializes instance variables and performs key and
        digest manipulation before updating the outer and inner states of the object.

        Args:
            key (bytes): Required to be passed as an argument during construction
                of the object.
            msg (object): Optional, it is used to update the message digest with
                additional data.
            digestmod (str): Required to be set to a hash function name, such as
                `md5`, `sha256`, or `ripemd160`.

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
        In the `HMAC` class generates a unique string identifier for the inner
        object's name, appending it to "-hmac-".

        Returns:
            str: A concatenation of the string "hmac-" and the value of its inner
            attribute `name`.

        """
        return "hmac-" + self.inner.name

    def update(self, msg):
        
        """
        Updates the inner state of an instance of the `HMAC` class with the given
        message `msg`.

        Args:
            msg (objectinstance): Updated with an object or instance value by
                calling the update method on it.

        """
        self.inner.update(msg)

    def copy(self):
        """
        Creates a new instance of the `HMAC` class with the same attributes as the
        original, except for the digest values which are copied and the inner and
        outer objects which are also copied.

        Returns:
            other: An instance of the same class as the original object, containing
            copied values of `digest_cons`, `digest_size`, `inner`, and `outer`.

        """
        other = self.__class__.__new__(self.__class__)
        other.digest_cons = self.digest_cons
        other.digest_size = self.digest_size
        other.inner = self.inner.copy()
        other.outer = self.outer.copy()
        return other

    def _current(self):
        """
        Updates the outer object's state by copying the inner digest and merging
        it with the existing outer state, returning the updated outer state.

        """
        h = self.outer.copy()
        h.update(self.inner.digest())
        return h

    def digest(self):
        """
        Computes the digest of the current state of an HMAC object using the
        underlying hash function.

        Returns:
            hmacdigest: A subclass of bytes representing the result of hashing the
            current state of the HMAC algorithm.

        """
        h = self._current()
        return h.digest()

    def hexdigest(self):
        """
        In the `HMAC` class generates the hexadecimal digest of the current state
        of the object's internal buffer using the `hexdigest` method of the `hashlib`
        module.

        Returns:
            str: A hexadecimal representation of the current value of an object.

        """
        h = self._current()
        return h.hexdigest()

def new(key, msg = None, digestmod = None):
    return HMAC(key, msg, digestmod)


def digest(key, msg, digest):
    """
    Takes a key, message, and digest as input and performs an authentication or
    message integrity check using either OpenSSL's HMAC method or Hashlib's SHA-256
    hash function, depending on the type of digest provided.

    Args:
        key (str): Used for hashing purposes.
        msg (str): Passed as input to the function for hashing.
        digest (OpenSSLHMACDigest): Used to specify the hash algorithm for the
            message digest calculation.

    Returns:
        bytes: The result of applying a message authentication code (MAC) to the
        given `key`, `msg`, and `digest` parameters using OpenSSL or hashlib library.

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
