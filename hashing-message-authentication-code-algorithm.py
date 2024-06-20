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
   
    blocksize = 64  # 512-bit HMAC; can be changed in subclasses.

    def __init__(self, key, msg = None, digestmod = None):
        
        """
        Sets up an object for a secure hash, taking key and digestmod as input.
        It checks the types of key and digestmod, sets the inner and outer hash
        objects, determines block size, updates the outer hash with the key, and
        optionally updates the inner hash with a given message.

        Args:
            key (`bytes` or `bytearray`.): hashable value that will be used to
                generate a message digest.
                
                	* `key`: A bytes or bytearray object, which is expected as input
                to the constructor.
                	* `digestmod`: An optional parameter that represents the digest
                module to be used for hashing. If it is not provided, a default
                value will be assigned.
                	* `callable` / `str`: The `digestmod` parameter can be either a
                callable function or a string representing a digest algorithm. If
                it is a callable function, the inner `digest_cons` function will
                take the digest module as an argument. Otherwise, the default
                digest module will be assigned to the `self.digest_cons` attribute.
                	* `blocksize`: The block size of the hashing algorithm used in
                the `digestmod` function. If this parameter is not present in the
                input digest object, the default value will be assigned.
                	* `inner`: An instance of the `hashlib.new()` class, which is
                created by calling the `lambda` function with the block size as
                an argument.
                	* `outer`: An instance of the same `hashlib.new()` class as
                `inner`, but created by calling the original `lambda` function
                without any arguments.
                	* `digest_size`: The size of the digest output, which is automatically
                computed based on the value assigned to `blocksize`.
                
                	Inside the constructor, the input `key` is processed as follows:
                
                	* If its length exceeds the block size, the original `key` is
                passed directly to the inner `digest_cons` function.
                	* Otherwise, the `key` is padded with zero bytes to the block
                size using the `ljust()` method.
                	* The resulting padded `key` is then used as input to the outer
                `digest_cons` function for hashing.
            msg (str): 2nd argument of the update() method, which allows the
                function to take into account additional information that needs
                to be incorporated into the digest calculation after the key has
                been processed.
            digestmod (str): message digest algorithm to use for hashing the key,
                and if it is none, a `ValueError` is raised.

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
        return "hmac-" + self.inner.name

    def update(self, msg):
        
        self.inner.update(msg)

    def copy(self):
        """
        Creates a shallow copy of the current instance, copying the `digest_cons`,
        `digest_size`, `inner`, and `outer` attributes.

        Returns:
            undefined: a new instance of the same class as the original, with
            identical internal and external states.
            
            	* `other`: A new instance of the same class as the original object,
            with some properties assigned from the original object.
            	* `digest_cons`: The digest constants for the new object are the same
            as those for the original object.
            	* `digest_size`: The size of the digest for the new object is the
            same as that of the original object.
            	* `inner`: A shallow copy of the inner attribute of the original object.
            	* `outer`: A shallow copy of the outer attribute of the original object.

        """
        other = self.__class__.__new__(self.__class__)
        other.digest_cons = self.digest_cons
        other.digest_size = self.digest_size
        other.inner = self.inner.copy()
        other.outer = self.outer.copy()
        return other

    def _current(self):
        """
        Creates a new instance of its outer class and copies the current object's
        attributes into it, then updates those attributes with the inner object's
        digest result.

        Returns:
            undefined: a new hash object that represents the concatenation of the
            outer and inner hashes.
            
            	* `h`: A copy of the outer dictionary, `self.outer`, created by calling
            `self.outer.copy()`.
            	* `update()`: The method that updates the inner dictionary,
            `self.inner.digest()`, is applied to the `h` dictionary, resulting in
            changes made to the original inner dictionary reflected in `h`.

        """
        h = self.outer.copy()
        h.update(self.inner.digest())
        return h

    def digest(self):
        h = self._current()
        return h.digest()

    def hexdigest(self):
        h = self._current()
        return h.hexdigest()

def new(key, msg = None, digestmod = None):
    return HMAC(key, msg, digestmod)


def digest(key, msg, digest):
    """
    Takes a key, message, and digest as input and performs HMAC calculation using
    OpenSSL or hashlib library, depending on the type of digest provided. It also
    adjusts the length of the key to fit within a specific block size to improve
    performance.

    Args:
        key (str): cryptographic key used for message authentication code (MAC) generation.
        msg (str): message that is being encrypted and is used in the HMAC computation
            along with the `key` input parameter.
        digest (str): message digest algorithm to be used for hashing, and its
            value determines whether the function will use the `hmac_digest()`
            method of the OpenSSL library or a lambda function to generate the
            hash value.

    Returns:
        undefined: a hash value generated using the given algorithm and key.
        
        	* `digest()` returns the generated digest as a bytes object.
        	* The digest is created using the `hmac_digest()` function from the
        `_hashopenssl` module if `isinstance(digest, str)` and `digest in _openssl_md_meths)`.
        	* If `digest` is a callable, it is called with the `b''` argument to
        generate the digest.
        	* If `digest` is not a string or a callable, it is assumed to be a class
        instance that provides a `digest()` method for generating the digest.
        	* The `inner` and `outer` variables are used to update the key with a
        block of size 64 bytes, and then the message to be signed is appended to
        the updated key.
        	* The `blocksize` attribute of the inner variable is used to determine
        the size of the block of bytes to be used for the key update.
        	* If the length of the key is longer than the block size, the key is
        padded with ASCII zeros to make it a multiple of the block size.
        	* The `trans_36` and `trans_5C` variables are used to perform byte-level
        operations on the key, such as translation and padding, as necessary for
        the digest algorithm.

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
