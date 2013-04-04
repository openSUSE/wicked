/*
 * Helper to call modprobe
 *
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */

#ifndef __WICKED_MODPROBE_H__
#define __WICKED_MODPROBE_H__

extern int	ni_modprobe(const char *module, const char *options);

#endif /* __WICKED_MODPROBE_H__ */
