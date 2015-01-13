# -*- coding: utf-8 -*-
"""
Extensible permission system for pybbm
"""

from __future__ import unicode_literals
from django.db.models import Q

from pybb import defaults, util
from pybb.models import Topic, PollAnswerUser

# Returns a list of groups that the user passed is allowed
# to view
def get_viewable_groups(user):
    if user.is_authenticated():
        user_group = user.groups.all()[0].name
    else:
        return ['Applicant']
    
    if user_group == 'Reject':
        return ['Applicant']
    elif user_group == 'Applicant':
        return ['Applicant']
    elif user_group == 'Trial':
        return ['Member', 'Applicant']
    elif user_group == 'Member':
        return ['Member', 'Applicant']
    elif user_group == 'Officer':
        return ['Officer', 'Member', 'Applicant']
    
class DefaultPermissionHandler(object):
    """ 
    Default Permission handler. If you want to implement custom permissions (for example,
    private forums based on some application-specific settings), you can inherit from this
    class and override any of the `filter_*` and `may_*` methods. Methods starting with
    `may` are expected to return `True` or `False`, whereas methods starting with `filter_*`
    should filter the queryset they receive, and return a new queryset containing only the
    objects the user is allowed to see.
    
    To activate your custom permission handler, set `settings.PYBB_PERMISSION_HANDLER` to
    the full qualified name of your class, e.g. "`myapp.pybb_adapter.MyPermissionHandler`".    
    """
    #
    # permission checks on categories
    #
    def filter_categories(self, user, qs):
        viewable_groups = get_viewable_groups(user)
        try:
            return qs.filter(group__in=viewable_groups)
        except ValueError:
            return qs
        
    def may_view_category(self, user, category):
        """ return True if `user` may view this category, False if not """
        if not user.is_authenticated():
            print "YUCKSTER"
            return False
        viewable_groups = get_viewable_groups(user)
        if category.group in viewable_groups:
            return True
        else:
            return False

    # 
    # permission checks on forums
    # 
    def filter_forums(self, user, qs):
        """ return a queryset with forums `user` is allowed to see """
        viewable_groups = get_viewable_groups(user)
        try:
            return qs.filter(group__in=viewable_groups)
        except ValueError:
            return qs
        
    def may_view_forum(self, user, forum):
        """ return True if user may view this forum, False if not """
        if not user.is_authenticated():
            print "YUCKYDOOPLE"
            return False
        viewable_groups = get_viewable_groups(user)
        if forum.group in viewable_groups:
            return True
        else:
            return False

    def may_create_topic(self, user, forum):
        """ return True if `user` is allowed to create a new topic in `forum` """
        return user.has_perm('pybb.add_post')

    #
    # permission checks on topics
    # 
    def filter_topics(self, user, qs):
        """ return a queryset with topics `user` is allowed to see """
        viewable_groups = get_viewable_groups(user)
        try:
            return qs.filter(group__in=viewable_groups)
        except ValueError:
            return qs
        
    def may_view_topic(self, user, topic):
        """ return True if user may view this topic, False otherwise """
        if not user.is_authenticated():
            if topic.group != "Applicant":
                return False
        viewable_groups = get_viewable_groups(user)
        if topic.group in viewable_groups:
            return True
        else:
            return False

    def may_moderate_topic(self, user, topic):
        return user.is_superuser or user in topic.forum.moderators.all()

    def may_close_topic(self, user, topic):
        """ return True if `user` may close `topic` """
        return self.may_moderate_topic(user, topic)

    def may_open_topic(self, user, topic):
        """ return True if `user` may open `topic` """
        return self.may_moderate_topic(user, topic)

    def may_stick_topic(self, user, topic):
        """ return True if `user` may stick `topic` """
        return self.may_moderate_topic(user, topic)

    def may_unstick_topic(self, user, topic):
        """ return True if `user` may unstick `topic` """
        return self.may_moderate_topic(user, topic)

    def may_vote_in_topic(self, user, topic):
        """ return True if `user` may unstick `topic` """
        return (
            user.is_authenticated() and topic.poll_type != Topic.POLL_TYPE_NONE and not topic.closed and
            not PollAnswerUser.objects.filter(poll_answer__topic=topic, user=user).exists()
        )

    def may_create_post(self, user, topic):
        """ return True if `user` is allowed to create a new post in `topic` """

        if topic.forum.hidden and (not user.is_staff):
            # if topic is hidden, only staff may post
            return False

        if topic.closed and (not user.is_staff):
            # if topic is closed, only staff may post
            return False

        # only user which have 'pybb.add_post' permission may post
        return defaults.PYBB_ENABLE_ANONYMOUS_POST or user.has_perm('pybb.add_post')

    def may_post_as_admin(self, user):
        """ return True if `user` may post as admin """
        return user.is_staff

    #
    # permission checks on posts
    #    
    def filter_posts(self, user, qs):
        """ return a queryset with posts `user` is allowed to see """
        viewable_groups = get_viewable_groups(user)
        try:
            return qs.filter(group__in=viewable_groups)
        except ValueError:
            return qs

    def may_view_post(self, user, post):
        """ return True if `user` may view `post`, False otherwise """
        if not user.is_authenticated():
            if post.group != "Applicant":
                return False
        viewable_groups = get_viewable_groups(user)
        if post.group in viewable_groups:
            return True
        else:
            return False

    def may_edit_post(self, user, post):
        """ return True if `user` may edit `post` """
        return user.is_superuser or post.user == user or self.may_moderate_topic(user, post.topic)

    def may_delete_post(self, user, post):
        """ return True if `user` may delete `post` """
        return self.may_moderate_topic(user, post.topic)

    #
    # permission checks on users
    #
    def may_block_user(self, user, user_to_block):
        """ return True if `user` may block `user_to_block` """
        return user.has_perm('pybb.block_users')

    def may_attach_files(self, user):
        """
        return True if `user` may attach files to posts, False otherwise.
        By default controlled by PYBB_ATTACHMENT_ENABLE setting
        """
        return defaults.PYBB_ATTACHMENT_ENABLE

    def may_create_poll(self, user):
        """
        return True if `user` may attach files to posts, False otherwise.
        By default always True
        """
        return True


perms = util.resolve_class(defaults.PYBB_PERMISSION_HANDLER)
