include $(TOPDIR)/rules.mk

PKG_NAME:=clarissa
PKG_VERSION:=v0.6
PKG_RELEASE:=0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://gitlab.com/evils/clarissa/-/archive/$(PKG_VERSION)/clarissa-$(PKG_VERSION).tar.gz
PKG_MIRROR_HASH:=f5588b5471ba6429b91c9dde7fafda403b159aa6d0a9220147b8a6b650c771db

include $(INCLUDE_DIR)/package.mk

define Package/clarissa
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Network census daemon
  URL:=https://gitlab.com/evils/clarissa
  DEPENDS:=+libpcap
endef

define Package/clarissa/description
  Clarissa is a daemon which keeps track of connected MAC addresses on a network.
  It can report these with sub-second resolution and can monitor passively.
  Currently includes a utility to report a count of known and unknown addresses.
endef

define Package/clarissa/build
	$(call Build/Compile/Default,SYSDINST=false)

define Package/clarissa/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR) $(1)/usr/sbin
endef

define Package/clarissa/postrm
	#!/usr/bin/env sh
	rm -rf /tmp/clar_*

$(eval $(call BuildPackage,clarissa))
