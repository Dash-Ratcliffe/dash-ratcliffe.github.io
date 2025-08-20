---
layout: default
title: My Homepage
---

## Hack The Box Writeups

<p class="page-intro">This page hosts all my Hack The Box machine writeups. Below is a complete list, with the most recent entries first.</p>

<ul class="writeup-list">
  {% for writeup in site.writeups reversed %}
    <li class="writeup-item">
      <div class="writeup-meta">
        <span class="writeup-date">{{ writeup.date | date: "%B %d, %Y" }}</span>
      </div>
      <h3 class="writeup-title">
        <a href="{{ writeup.url }}">{{ writeup.title }}</a>
      </h3>
      <div class="writeup-tags">
        {% for tag in writeup.tags %}
          <span class="tag">{{ tag }}</span>
        {% endfor %}
      </div>
    </li>
  {% endfor %}
</ul>
