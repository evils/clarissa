include $(TOPDIR)/rules.mk

PKG_NAME:=clarissa
PKG_RELEASE:=0

# tag or `git describe --tags` or just a commit hash
PKG_VERSION:=v1.0
PKG_HASH:=0000000000000000000000000000000000000000000000000000000000000000

PKG_SOURCE_URL:=https://gitlab.com/evils/clarissa/-/archive/$(PKG_VERSION)
PKG_SOURCE:=clarissa-$(PKG_VERSION).tar.gz

PKG_MAINTAINER:=Evils <evils.devils@protonmail.com>
PKG_LICENSE:=BSD-3-CLAUSE
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

define Build/Compile
  $(call Build/Compile/Default,clarissa)
endef

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
endef

define Package/clarissa/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/clarissa $(1)/usr/bin

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/distros/openwrt/clarissa.init $(1)/etc/init.d/clarissa
endef

define Package/clarissa/postrm
	#!/usr/bin/env sh
	rm -rf /var/run/clar/
endef

$(eval $(call BuildPackage,clarissa))
