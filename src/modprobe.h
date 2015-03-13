/*
 * Helper to call modprobe
 *
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */

#ifndef __WICKED_MODPROBE_H__
#define __WICKED_MODPROBE_H__

#ifndef NI_MODPROBE_BIN
#define NI_MODPROBE_BIN "/sbin/modprobe"
#endif
#ifndef NI_MODPROBE_LOAD_OPT
#define NI_MODPROBE_LOAD_OPT "-qs"
#endif
#ifndef NI_MODPROBE_REMOVE_OPT
#define NI_MODPROBE_REMOVE_OPT "-rqs"
#endif

extern int	ni_modprobe(const char *options, const char *module, const char *moptions);

#endif /* __WICKED_MODPROBE_H__ */
