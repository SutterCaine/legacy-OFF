DIST_SUBDIRS = secp256k1
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)

if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(CXXFLAGS) $(CPPFLAGS)"
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include

LIBBITCOIN_SERVER=liboffering_server.a
LIBBITCOIN_WALLET=liboffering_wallet.a
LIBBITCOIN_COMMON=liboffering_common.a
LIBBITCOIN_CLI=liboffering_cli.a
LIBBITCOIN_UTIL=liboffering_util.a
LIBBITCOIN_CRYPTO=crypto/liboffering_crypto.a
LIBBITCOIN_UNIVALUE=univalue/liboffering_univalue.a
LIBBITCOINQT=qt/libofferingqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES = \
  crypto/liboffering_crypto.a \
  liboffering_util.a \
  liboffering_common.a \
  univalue/liboffering_univalue.a \
  liboffering_server.a \
  liboffering_cli.a
if ENABLE_WALLET
BITCOIN_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += liboffering_wallet.a
endif

if BUILD_BITCOIN_LIBS
lib_LTLIBRARIES = libofferingconsensus.la
LIBBITCOIN_CONSENSUS=libofferingconsensus.la
else
LIBBITCOIN_CONSENSUS=
endif

bin_PROGRAMS =
TESTS =

if BUILD_BITCOIND
  bin_PROGRAMS += offeringd
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += offering-cli offering-tx
endif

.PHONY: FORCE
# offering core #
BITCOIN_CORE_H = \
  addrman.h \
  alert.h \
  allocators.h \
  amount.h \
  base58.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compressor.h \
  core_io.h \
  crypter.h \
  crypto/sph_types.h \
  crypto/sph_blake.h \
  crypto/sph_groestl.h \
  crypto/sph_keccak.h \
  crypto/sph_bmw.h \
  crypto/sph_jh.h \
  crypto/sph_skein.h \
  db.h \
  eccryptoverify.h \
  ecwrapper.h \
  hash.h \
  hashblock.h \
  init.h \
  key.h \
  keystore.h \
  leveldbwrapper.h \
  limitedmap.h \
  main.h \
  merkleblock.h \
  miner.h \
  mruset.h \
  netbase.h \
  net.h \
  noui.h \
  pow.h \
  protocol.h \
  primitives/block.h \
  primitives/transaction.h \
  pubkey.h \
  random.h \
  rpcclient.h \
  rpcprotocol.h \
  rpcserver.h \
  script/interpreter.h \
  script/script.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/script_error.h \
  serialize.h \
  streams.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  undo.h \
  util.h \
  utilstrencodings.h \
  utilmoneystr.h \
  utiltime.h \
  version.h \
  wallet.h \
  wallet_ismine.h \
  walletdb.h \
  compat/sanity.h

JSON_H = \
  json/json_spirit.h \
  json/json_spirit_error_position.h \
  json/json_spirit_reader.h \
  json/json_spirit_reader_template.h \
  json/json_spirit_stream_reader.h \
  json/json_spirit_utils.h \
  json/json_spirit_value.h \
  json/json_spirit_writer.h \
  json/json_spirit_writer_template.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
liboffering_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between offeringd and offering-qt
liboffering_server_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS)
liboffering_server_a_SOURCES = \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  init.cpp \
  leveldbwrapper.cpp \
  main.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  rest.cpp \
  rpcblockchain.cpp \
  rpcmining.cpp \
  rpcmisc.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcserver.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  txdb.cpp \
  txmempool.cpp \
  $(JSON_H) \
  $(BITCOIN_CORE_H)

# wallet: shared between offeringd and offering-qt, but only linked
# when wallet enabled
liboffering_wallet_a_CPPFLAGS = $(BITCOIN_INCLUDES)
liboffering_wallet_a_SOURCES = \
  db.cpp \
  crypter.cpp \
  rpcdump.cpp \
  rpcwallet.cpp \
  wallet.cpp \
  wallet_ismine.cpp \
  walletdb.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_liboffering_crypto_a_CFLAGS = -fPIC
crypto_liboffering_crypto_a_CPPFLAGS = $(BITCOIN_CONFIG_INCLUDES)
crypto_liboffering_crypto_a_SOURCES = \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/hmac_sha256.cpp \
  crypto/rfc6979_hmac_sha256.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/common.h \
  crypto/sha256.h \
  crypto/sha512.h \
  crypto/hmac_sha256.h \
  crypto/rfc6979_hmac_sha256.h \
  crypto/hmac_sha512.h \
  crypto/sha1.h \
  crypto/ripemd160.h \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/groestl.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/skein.c \
  crypto/sph_types.h \
  crypto/sph_blake.h \
  crypto/sph_groestl.h \
  crypto/sph_keccak.h \
  crypto/sph_bmw.h \
  crypto/sph_jh.h \
  crypto/sph_skein.h

# univalue JSON library
univalue_liboffering_univalue_a_SOURCES = \
  univalue/univalue.cpp \
  univalue/univalue_read.cpp \
  univalue/univalue_write.cpp \
  univalue/univalue_escapes.h \
  univalue/univalue.h

# common: shared between offeringd, and offering-qt and non-server tools
liboffering_common_a_CPPFLAGS = $(BITCOIN_INCLUDES)
liboffering_common_a_SOURCES = \
  allocators.cpp \
  amount.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  eccryptoverify.cpp \
  ecwrapper.cpp \
  hash.cpp \
  key.cpp \
  keystore.cpp \
  netbase.cpp \
  pow.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/sign.cpp \
  script/standard.cpp \
  script/script_error.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
liboffering_util_a_CPPFLAGS = $(BITCOIN_INCLUDES)
liboffering_util_a_SOURCES = \
  compat/strnlen.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  random.cpp \
  rpcprotocol.cpp \
  sync.cpp \
  uint256.cpp \
  util.cpp \
  utilstrencodings.cpp \
  utilmoneystr.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT
liboffering_util_a_SOURCES += compat/glibc_compat.cpp
liboffering_util_a_SOURCES += compat/glibcxx_compat.cpp
endif

# cli: shared between offering-cli and offering-qt
liboffering_cli_a_CPPFLAGS = $(BITCOIN_INCLUDES)
liboffering_cli_a_SOURCES = \
  rpcclient.cpp \
  $(BITCOIN_CORE_H)

nodist_liboffering_util_a_SOURCES = $(srcdir)/obj/build.h
#

# offeringd binary #
offeringd_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

if ENABLE_WALLET
offeringd_LDADD += liboffering_wallet.a
endif
offeringd_SOURCES = bitcoind.cpp
#

if TARGET_WINDOWS
offeringd_SOURCES += bitcoind-res.rc
endif

offeringd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS)
offeringd_CPPFLAGS = $(BITCOIN_INCLUDES)
offeringd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

# offering-cli binary #
offering_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_UTIL) \
  $(BOOST_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS)

offering_cli_SOURCES = \
  bitcoin-cli.cpp

offering_cli_CPPFLAGS = $(BITCOIN_INCLUDES)
#

# offering-tx binary #
offering_tx_LDADD = \
  $(LIBBITCOIN_UNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSECP256K1) \
  $(BOOST_LIBS) \
  $(CRYPTO_LIBS)

offering_tx_SOURCES = bitcoin-tx.cpp
offering_tx_CPPFLAGS = $(BITCOIN_INCLUDES)
#
offering_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
offering_cli_SOURCES += bitcoin-cli-res.rc
endif
offering_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libofferingconsensus_la_SOURCES = \
  primitives/transaction.cpp \
  crypto/hmac_sha512.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/ripemd160.cpp \
  eccryptoverify.cpp \
  ecwrapper.cpp \
  hash.cpp \
  pubkey.cpp \
  script/script.cpp \
  script/interpreter.cpp \
  script/bitcoinconsensus.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libofferingconsensus_la_SOURCES += compat/glibc_compat.cpp
  libofferingconsensus_la_SOURCES += compat/glibcxx_compat.cpp
endif

libofferingconsensus_la_LDFLAGS = -no-undefined $(RELDFLAGS)
libofferingconsensus_la_LIBADD = $(CRYPTO_LIBS)
libofferingconsensus_la_CPPFLAGS = $(CRYPTO_CFLAGS) -I$(builddir)/obj -DBUILD_BITCOIN_INTERNAL
if USE_LIBSECP256K1
libofferingconsensus_la_LIBADD += secp256k1/libsecp256k1.la
endif
endif

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(CXXFLAGS)  -c -o $@ $<

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
