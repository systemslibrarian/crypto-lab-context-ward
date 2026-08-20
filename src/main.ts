import './style.css'
import { mount } from './ui/app.ts'

const root = document.getElementById('app')
if (root) {
  void mount(root as HTMLElement)
}
