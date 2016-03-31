#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=molmc-imlink
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/molmc-imlink
  SECTION:=net
  CATEGORY:=Intorobot
  DEPENDS:=+libpcap +libpthread +libopenssl +libnl +wireless-tools +ethtool
  TITLE:=Smartconfig tools for quick wifi-connection
  URL:=http://www.intorobot.com/
  MAINTAINER:=CH <support@molmc.com>
endef

define Package/molmc-imlink/description
  Smartconfig tools for quick wifi-connection
endef

MAKE_FLAGS += prefix=/usr \
	libnl=true \
	sqlite=false \
	unstable=false \
	OSNAME=Linux

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(MAKE_FLAGS)
endef

define Package/molmc-imlink/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/imlink-dump $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/imlink-response $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/iwscan-list $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/imlink_config_wifi $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sc_config_kill $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/airmon-ng $(1)/usr/sbin/imlink-mon
endef

$(eval $(call BuildPackage,molmc-imlink))
